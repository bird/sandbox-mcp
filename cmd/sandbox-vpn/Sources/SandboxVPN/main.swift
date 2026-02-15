import Foundation
import Virtualization

enum CLIError: Error {
    case message(String)
}

private func eprint(_ s: String) {
    if let data = (s + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

private func jsonEscape(_ s: String) -> String {
    var out = ""
    out.reserveCapacity(s.count)
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\\": out += "\\\\"
        case "\"": out += "\\\""
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04X", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out
}

private func parseArgs(_ argv: [String]) throws -> VMConfig {
    var kernelPath: String?
    var rootfsPath: String?
    var socketPath: String?
    var cpus = 2
    var memoryMB = 512
    var enableVsock = false

    var i = 1
    while i < argv.count {
        let arg = argv[i]
        switch arg {
        case "--kernel":
            i += 1
            guard i < argv.count else { throw CLIError.message("--kernel requires PATH") }
            kernelPath = argv[i]
        case "--rootfs":
            i += 1
            guard i < argv.count else { throw CLIError.message("--rootfs requires PATH") }
            rootfsPath = argv[i]
        case "--socket-path":
            i += 1
            guard i < argv.count else { throw CLIError.message("--socket-path requires PATH") }
            socketPath = argv[i]
        case "--cpus":
            i += 1
            guard i < argv.count else { throw CLIError.message("--cpus requires INT") }
            guard let v = Int(argv[i]), v > 0 else { throw CLIError.message("--cpus must be > 0") }
            cpus = v
        case "--memory":
            i += 1
            guard i < argv.count else { throw CLIError.message("--memory requires INT (MB)") }
            guard let v = Int(argv[i]), v > 0 else { throw CLIError.message("--memory must be > 0") }
            memoryMB = v
        case "--virtio-vsock":
            enableVsock = true
        default:
            throw CLIError.message("unknown arg: \(arg)")
        }

        i += 1
    }

    guard let kernelPath else { throw CLIError.message("missing --kernel") }
    guard let rootfsPath else { throw CLIError.message("missing --rootfs") }
    guard let socketPath else { throw CLIError.message("missing --socket-path") }

    return VMConfig(
        kernelPath: kernelPath,
        rootfsPath: rootfsPath,
        cpuCount: cpus,
        memoryMB: memoryMB,
        socketPath: socketPath,
        enableVsock: enableVsock
    )
}

final class App: NSObject, VZVirtualMachineDelegate, @unchecked Sendable {
    let vm: VZVirtualMachine
    private let lock = NSLock()
    private var didShutdown = false
    private var intSrc: DispatchSourceSignal?
    private var termSrc: DispatchSourceSignal?

    init(vm: VZVirtualMachine) {
        self.vm = vm
        super.init()
    }

    func installSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let sigQueue = DispatchQueue(label: "sandbox-vpn.signals")

        let intSrc = DispatchSource.makeSignalSource(signal: SIGINT, queue: sigQueue)
        intSrc.setEventHandler { [weak self] in
            self?.shutdown("sigint")
        }
        intSrc.resume()
        self.intSrc = intSrc

        let termSrc = DispatchSource.makeSignalSource(signal: SIGTERM, queue: sigQueue)
        termSrc.setEventHandler { [weak self] in
            self?.shutdown("sigterm")
        }
        termSrc.resume()
        self.termSrc = termSrc
    }

    func shutdown(_ reason: String) {
        lock.lock()
        if didShutdown {
            lock.unlock()
            return
        }
        didShutdown = true
        lock.unlock()

        Task { @MainActor in
            _ = stopRelay(for: vm)
            try? vm.requestStop()

            try? await Task.sleep(for: .seconds(2))

            if vm.state == .running {
                vm.stop { _ in
                    CFRunLoopStop(CFRunLoopGetMain())
                }
            } else {
                CFRunLoopStop(CFRunLoopGetMain())
            }
        }
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        eprint("sandbox-vpn: vm stopped with error: \(error)")
        shutdown("vm_error")
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        shutdown("vm_stop")
    }
}

let config: VMConfig
do {
    config = try parseArgs(CommandLine.arguments)
} catch {
    eprint("sandbox-vpn: \(error)")
    exit(2)
}

let vm: VZVirtualMachine
do {
    vm = try bootVM(config: config)
} catch {
    eprint("sandbox-vpn: boot failed: \(error)")
    exit(1)
}

let pid = getpid()
let json = "{\"pid\": \(pid), \"socket\": \"\(jsonEscape(config.socketPath))\"}"
if let data = (json + "\n").data(using: .utf8) {
    FileHandle.standardOutput.write(data)
}

let app = App(vm: vm)
vm.delegate = app
app.installSignalHandlers()

RunLoop.main.run()
