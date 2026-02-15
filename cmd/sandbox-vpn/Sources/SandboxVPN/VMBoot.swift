import Foundation
import Virtualization
import Darwin

struct VMConfig {
    let kernelPath: String
    let rootfsPath: String
    let cpuCount: Int
    let memoryMB: Int
    let socketPath: String
    let enableVsock: Bool
}

enum VMBootError: Error {
    case message(String)
    case posix(String, Int32)
}

private func throwPOSIX(_ op: String) throws -> Never {
    throw VMBootError.posix(op, errno)
}

private func setNoSigPipe(fd: Int32) {
    var one: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one)))
}

private func setNonBlocking(fd: Int32) {
    let flags = fcntl(fd, F_GETFL)
    if flags >= 0 {
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }
}

final class SocketRelay {
    private let socketPath: String
    private let frameFD: Int32
    private let queue = DispatchQueue(label: "sandbox-vpn.relay", attributes: .concurrent)
    private var serverFD: Int32 = -1
    private var running = false

    init(socketPath: String, frameFD: Int32) {
        self.socketPath = socketPath
        self.frameFD = frameFD
    }

    func start() throws {
        guard !running else { return }
        running = true
        var started = false
        defer {
            if !started {
                running = false
                if serverFD >= 0 {
                    close(serverFD)
                    serverFD = -1
                }
            }
        }

        socketPath.withCString { _ = unlink($0) }

        let fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)
        if fd < 0 { try throwPOSIX("socket") }
        serverFD = fd
        setNoSigPipe(fd: fd)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8) + [0]
        if pathBytes.count > MemoryLayout.size(ofValue: addr.sun_path) {
            throw VMBootError.message("socket path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }

        let len = socklen_t(MemoryLayout.size(ofValue: addr))
        let bindResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, len)
            }
        }
        if bindResult != 0 {
            let err = errno
            close(fd)
            serverFD = -1
            errno = err
            try throwPOSIX("bind")
        }
        if listen(fd, 1) != 0 {
            let err = errno
            close(fd)
            serverFD = -1
            errno = err
            try throwPOSIX("listen")
        }

        queue.async { [weak self] in
            self?.acceptLoop()
        }

        started = true
    }

    func stop() {
        guard running else { return }
        running = false

        if serverFD >= 0 {
            close(serverFD)
            serverFD = -1
        }
        close(frameFD)
        socketPath.withCString { _ = unlink($0) }
    }

    private func acceptLoop() {
        while running {
            let clientFD = accept(serverFD, nil, nil)
            if clientFD < 0 {
                if errno == EINTR { continue }
                break
            }
            setNoSigPipe(fd: clientFD)

            relayClient(clientFD)
        }
    }

    private func relayClient(_ clientFD: Int32) {
        setNonBlocking(fd: clientFD)
        setNonBlocking(fd: frameFD)

        let doneSem = DispatchSemaphore(value: 0)
        let doneLock = NSLock()
        var done = false

        let cancelAllLock = NSLock()
        var cancelAll: (() -> Void)?

        func finish() {
            doneLock.lock()
            if done {
                doneLock.unlock()
                return
            }
            done = true
            doneLock.unlock()
            doneSem.signal()
        }

        func drain(from src: Int32, to dst: Int32) {
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            while running {
                let n = read(src, &buf, buf.count)
                if n == 0 {
                    cancelAllLock.lock()
                    cancelAll?()
                    cancelAllLock.unlock()
                    return
                }
                if n < 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK { return }
                    cancelAllLock.lock()
                    cancelAll?()
                    cancelAllLock.unlock()
                    return
                }

                var failed = false
                var blocked = false
                buf.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else {
                        failed = true
                        return
                    }
                    var off = 0
                    while off < n {
                        let m = write(dst, base.advanced(by: off), n - off)
                        if m < 0 {
                            if errno == EINTR { continue }
                            if errno == EAGAIN || errno == EWOULDBLOCK {
                                blocked = true
                                return
                            }
                            failed = true
                            return
                        }
                        off += m
                    }
                }
                if blocked { return }
                if failed {
                    cancelAllLock.lock()
                    cancelAll?()
                    cancelAllLock.unlock()
                    return
                }
            }
        }

        let clientSrc = DispatchSource.makeReadSource(fileDescriptor: clientFD, queue: queue)
        let frameSrc = DispatchSource.makeReadSource(fileDescriptor: frameFD, queue: queue)

        cancelAll = {
            clientSrc.cancel()
            frameSrc.cancel()
            finish()
        }

        clientSrc.setEventHandler {
            drain(from: clientFD, to: self.frameFD)
        }
        frameSrc.setEventHandler {
            drain(from: self.frameFD, to: clientFD)
        }
        clientSrc.setCancelHandler {
            close(clientFD)
        }

        clientSrc.resume()
        frameSrc.resume()
        doneSem.wait()
    }
}

extension SocketRelay: @unchecked Sendable {}

final class RelayRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var relays = [ObjectIdentifier: SocketRelay]()

    func set(_ relay: SocketRelay, for vm: VZVirtualMachine) {
        lock.lock()
        relays[ObjectIdentifier(vm)] = relay
        lock.unlock()
    }

    func remove(for vm: VZVirtualMachine) -> SocketRelay? {
        lock.lock()
        let relay = relays.removeValue(forKey: ObjectIdentifier(vm))
        lock.unlock()
        return relay
    }
}

private let relayRegistry = RelayRegistry()

@discardableResult
func stopRelay(for vm: VZVirtualMachine) -> Bool {
    let relay = relayRegistry.remove(for: vm)
    relay?.stop()
    return relay != nil
}

func bootVM(config: VMConfig) throws -> VZVirtualMachine {
    var fds = [Int32](repeating: -1, count: 2)
    if socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) != 0 {
        try throwPOSIX("socketpair")
    }
    var vmNICFD = fds[0]
    var hostFD = fds[1]
    defer {
        if vmNICFD >= 0 { close(vmNICFD) }
        if hostFD >= 0 { close(hostFD) }
    }
    setNoSigPipe(fd: vmNICFD)
    setNoSigPipe(fd: hostFD)

    let kernelURL = URL(fileURLWithPath: config.kernelPath)
    let rootfsURL = URL(fileURLWithPath: config.rootfsPath)

    let bootLoader = VZLinuxBootLoader(kernelURL: kernelURL)

    let diskAttachment = try VZDiskImageStorageDeviceAttachment(url: rootfsURL, readOnly: false)
    let blockDevice = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)

    let nicHandle = FileHandle(fileDescriptor: vmNICFD, closeOnDealloc: true)
    vmNICFD = -1
    let netAttachment = VZFileHandleNetworkDeviceAttachment(fileHandle: nicHandle)
    let netDevice = VZVirtioNetworkDeviceConfiguration()
    netDevice.attachment = netAttachment

    let console = VZVirtioConsoleDeviceConfiguration()
    let consolePort = VZVirtioConsolePortConfiguration()
    consolePort.isConsole = true
    consolePort.name = "console"
    consolePort.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle.standardInput,
        fileHandleForWriting: FileHandle.standardOutput
    )
    console.ports[0] = consolePort

    let configuration = VZVirtualMachineConfiguration()
    configuration.bootLoader = bootLoader
    configuration.cpuCount = config.cpuCount
    configuration.memorySize = UInt64(config.memoryMB) * 1024 * 1024
    configuration.storageDevices = [blockDevice]
    configuration.networkDevices = [netDevice]
    configuration.consoleDevices = [console]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
    if config.enableVsock {
        configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    }

    try configuration.validate()

    let vm = VZVirtualMachine(configuration: configuration)

    let relay = SocketRelay(socketPath: config.socketPath, frameFD: hostFD)
    try relay.start()
    hostFD = -1
    relayRegistry.set(relay, for: vm)

    let sem = DispatchSemaphore(value: 0)
    var startError: Error?
    vm.start { result in
        if case .failure(let error) = result {
            startError = error
        }
        sem.signal()
    }
    sem.wait()
    if let startError {
        _ = stopRelay(for: vm)
        throw startError
    }

    return vm
}
