from __future__ import print_function

import sys, os, re, time, socket, select, subprocess, errno, shutil, random, string, json
from subprocess import check_call, Popen
from optparse import OptionParser

__all__ = []

##################################################################
# Test structure
#

__all__ += ["test", "end_part", "run_tests", "get_current_test"]

RESULTS = {"details": []}
TESTS = []
TOTAL = POSSIBLE = 0
PART_TOTAL = PART_POSSIBLE = 0
CURRENT_TEST = None

def test(points, title=None, parent=None):
    """Decorator for declaring test functions.  If title is None, the
    title of the test will be derived from the function name by
    stripping the leading "test_" and replacing underscores with
    spaces."""

    def register_test(fn, title=title):
        if not title:
            assert fn.__name__.startswith("test_")
            title = fn.__name__[5:].replace("_", " ")
        if parent:
            title = "  " + title

        def run_test():
            global TOTAL, POSSIBLE, CURRENT_TEST

            # Handle test dependencies
            if run_test.complete:
                return run_test.ok
            run_test.complete = True
            parent_failed = False
            if parent:
                parent_failed = not parent()

            # Run the test
            fail = None
            start = time.time()
            CURRENT_TEST = run_test
            CURRENT_RESULT = {"title": title, "message": None}
            sys.stdout.write("== Test %s == " % title)
            if parent:
                sys.stdout.write("\n")
            sys.stdout.flush()
            try:
                if parent_failed:
                    raise AssertionError('Parent failed: %s' % parent.__name__)
                fn()
            except AssertionError as e:
                fail = str(e)
                if not fail:
                    fail = repr(e)

            # Display and handle test result
            POSSIBLE += points
            if points:
                print("%s: %s" % (title, \
                    (color("red", "FAIL") if fail else color("green", "OK"))), end=' ')
            if time.time() - start > 0.1:
                print("(%.1fs)" % (time.time() - start), end=' ')
            print()
            if fail:
                print("    %s" % fail.replace("\n", "\n    "))
                CURRENT_RESULT["score"] = 0
            else:
                TOTAL += points
                CURRENT_RESULT["score"] = points
            RESULTS["details"].append(CURRENT_RESULT)

            for callback in run_test.on_finish:
                callback(fail)
            CURRENT_TEST = None

            run_test.ok = not fail
            return run_test.ok

        # Record test metadata on the test wrapper function
        run_test.__name__ = fn.__name__
        run_test.title = title
        run_test.complete = False
        run_test.ok = False
        run_test.on_finish = []
        TESTS.append(run_test)
        return run_test
    return register_test

def end_part(name):
    def show_part():
        global PART_TOTAL, PART_POSSIBLE
        print("Part %s score: %d/%d" % \
            (name, TOTAL - PART_TOTAL, POSSIBLE - PART_POSSIBLE))
        print()
        PART_TOTAL, PART_POSSIBLE = TOTAL, POSSIBLE
    show_part.title = ""
    TESTS.append(show_part)

def run_tests():
    """Set up for testing and run the registered test functions."""

    # Handle command line
    global options
    parser = OptionParser(usage="usage: %prog [-v] [filters...]")
    parser.add_option("-v", "--verbose", action="store_true",
                      help="print commands")
    parser.add_option("--color", choices=["never", "always", "auto"],
                      default="auto", help="never, always, or auto")
    parser.add_option("-f", "--file", dest="filename",
                      help="store results to the json file")
    
    (options, args) = parser.parse_args()

    # Start with a full build to catch build errors
    make()

    # Clean the file system if there is one
    reset_fs()

    # Run tests
    limit = list(map(str.lower, args))
    try:
        for test in TESTS:
            if not limit or any(l in test.title.lower() for l in limit):
                test()
        RESULTS["score"] = TOTAL
        if not limit:
            print("Score: %d/%d" % (TOTAL, POSSIBLE))
    except KeyboardInterrupt:
        pass

    if options.filename:
        with open(options.filename, "w") as F:
            json.dump(RESULTS, F)

    if TOTAL < POSSIBLE:
        sys.exit(1)

def get_current_test():
    if not CURRENT_TEST:
        raise RuntimeError("No test is running")
    return CURRENT_TEST

##################################################################
# Blockchain Test structure
#

__all__ += ["config_fresh", "run_tests_bc", "read_exps", "MultiProcessesTester"]

from time import sleep

def split(output):
    outs = list()
    for line in output.strip().split('\n'):
        if line.startswith('$ '):
            outs.append(list())
        outs[-1].append(line)
    return outs

def match(outs, exps):
    try:
        assert len(outs) == len(exps)
        for out, exp in zip(outs, exps):
            assert str(out) == str(exp)
    except:
        return False
    return True

class MultiProcessesTester:
    def __init__(self, nodes, path="build/main"):
        self.status = "INIT"
        self.path = path
        self.nodes = nodes
        self.processes = {node: None for node in nodes}
        self.outputs = {node: {"ret": -1, "out": "", "err": ""} for node in nodes}

    def __exec(self, node, cmd):
        try:
            self.processes[node].stdin.write(cmd + '\n')
            self.processes[node].stdin.flush()
        except:
            pass
    
    def __read(self, node):
        try:
            out, err = self.processes[node].communicate(timeout=10)
            ret = self.processes[node].returncode
            self.outputs[node]["ret"] = ret
            self.outputs[node]["out"] = out
            self.outputs[node]["err"] = err
        except:
            pass
    
    def __kill(self, node):
        self.__exec(node, 'quit')
        subprocess.run(f"kill {self.processes[node].pid}", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    def startup(self):
        assert self.status == "INIT"
        self.status = "START"
        for node in self.nodes:
            self.processes[node] = subprocess.Popen([self.path, node], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def run(self, flows):
        for cmds in flows:
            for node, cmd in cmds:
                self.__exec(node, cmd)
            sleep(0.5)

    def shutdown(self):
        assert self.status == "START"
        self.status = "SHUT"
        for node in self.nodes:
            self.__kill(node)
            self.__read(node)
    
    def show(self, nodes):
        assert self.status == "SHUT"
        for node in nodes:
            print(node)
            print(self.outputs[node]["out"])

    def check(self, nodes, exps=None):
        assert self.status == "SHUT"
        outs = dict()
        for node in nodes:
            #print(f"Node: {node}, Ret: {self.outputs[node]['ret']}")
            assert self.outputs[node]["ret"] == 0
            outs[node] = split(self.outputs[node]["out"])
        if exps:
            for node in nodes:
                print(f"outs[{node}]: {outs[node]}, exps[{node}]: {exps[node]}")
                assert match(outs[node], exps[node])
        else:
            assert len(set(map(str, outs.values()))) == 1

def read_exps(path):
    exps = dict()
    for node in ["node1", "node2", "node3", "node4"]:
        with open(f'{path}/{node}.out', 'r') as f:
            exps[node] = split(f.read())
    return exps

def config_fresh(path):
    cmds = [
        "rm -rf build/config",
        "cp -r config build/config/",
        f"cp -r {path}/config/* build/config/"
    ]
    r = subprocess.run(" && ".join(cmds), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

def run_tests_bc():
    """Set up for testing and run the registered test functions."""

    # Handle command line
    global options
    parser = OptionParser(usage="usage: %prog [-v] [filters...]")
    parser.add_option("-v", "--verbose", action="store_true",
                      help="print commands")
    parser.add_option("--color", choices=["never", "always", "auto"],
                      default="auto", help="never, always, or auto")
    parser.add_option("-f", "--file", dest="filename",
                      help="store results to the json file")
    
    (options, args) = parser.parse_args()


    # Start with a full build to catch build errors
    make()

    # Run tests
    limit = list(map(str.lower, args))
    try:
        for test in TESTS:
            if not limit or any(l in test.title.lower() for l in limit):
                test()
        RESULTS["score"] = TOTAL
        if not limit:
            print("Score: %d/%d" % (TOTAL, POSSIBLE))
    except KeyboardInterrupt:
        pass

    if options.filename:
        with open(options.filename, "w") as F:
            json.dump(RESULTS, F)

    if TOTAL < POSSIBLE:
        sys.exit(1)


##################################################################
# Assertions
#

__all__ += ["assert_equal", "assert_lines_match"]

def assert_equal(got, expect, msg=""):
    if got == expect:
        return
    if msg:
        msg += "\n"
    raise AssertionError("%sgot:\n  %s\nexpected:\n  %s" %
                         (msg, str(got).replace("\n", "\n  "),
                          str(expect).replace("\n", "\n  ")))

def assert_lines_match(text, *exps, **kw):
    """Assert that all of exps match some line in text.  If a 'no'
    keyword argument is given, it must be a list of exps that must
    *not* match any line in text."""

    def assert_lines_match_kw(no=[], isregs=[], continued=False):
        return no, isregs, continued
    no, isregs, continued = assert_lines_match_kw(**kw)
    isregs += [True] * (len(exps) - len(isregs))
    # Check text against exps
    lines = text.splitlines()
    good = set()
    bad = set()
    prev_good = None
    for i, line in enumerate(lines):
        if any(re.match(r, line) for r in no):
            bad.add(i)
        if exps and continued and prev_good is not None and prev_good != i - 1:
            bad.add(i - 1)
        if exps and (re.match(exps[0], line) if isregs[0] else exps[0] == line.strip()):
            good.add(i)
            exps = exps[1:]
            isregs = isregs[1:]
            prev_good = i

    if not exps and not bad:
        return

    # We failed; construct an informative failure message
    show = set()
    for lineno in good.union(bad):
        for offset in range(-2, 3):
            show.add(lineno + offset)
    if exps:
        show.update(n for n in range(len(lines) - 5, len(lines)))

    msg = []
    last = -1
    for lineno in sorted(show):
        if 0 <= lineno < len(lines):
            if lineno != last + 1:
                msg.append("...")
            last = lineno
            msg.append("%s %s" % (color("red", "BAD ") if lineno in bad else
                                  color("green", "GOOD") if lineno in good
                                  else "    ",
                                  lines[lineno]))
    if last != len(lines) - 1:
        msg.append("...")
    if bad:
        msg.append("unexpected lines in output")
    for r in exps:
        msg.append(color("red", "MISSING") + " '%s'" % r)
    raise AssertionError("\n".join(msg))

##################################################################
# Utilities
#

__all__ += ["make", "maybe_unlink", "reset_fs", "color", "random_str", "check_time", "check_answers"]

MAKE_TIMESTAMP = 0

def pre_make():
    """Delay prior to running make to ensure file mtimes change."""
    while int(time.time()) == MAKE_TIMESTAMP:
        time.sleep(0.1)

def post_make():
    """Record the time after make completes so that the next run of
    make can be delayed if needed."""
    global MAKE_TIMESTAMP
    MAKE_TIMESTAMP = int(time.time())

def make(*target, stdout=None):
    pre_make()
    if Popen(("make",) + target, stdout=stdout).wait():
        sys.exit(1)
    post_make()

def show_command(cmd):
    from pipes import quote
    print("\n$", " ".join(map(quote, cmd)))

def maybe_unlink(*paths):
    for path in paths:
        try:
            os.unlink(path)
        except EnvironmentError as e:
            if e.errno != errno.ENOENT:
                raise

COLORS = {"default": "\033[0m", "red": "\033[31m", "green": "\033[32m"}

def color(name, text):
    if options.color == "always" or (options.color == "auto" and os.isatty(1)):
        return COLORS[name] + text + COLORS["default"]
    return text

def reset_fs():
    if os.path.exists("build/user/clean-user.img"):
        maybe_unlink("build/os.img")
        shutil.copyfile("build/user/clean-user.img", "build/user/user.img")

def random_str(n=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(n))

def check_time():
    try:
        print("")
        with open('time.txt') as f:
            d = f.read().strip()
            if not re.match(r'^\d+$', d):
                raise AssertionError('time.txt does not contain a single integer (number of hours spent on the lab)')
    except IOError:
        raise AssertionError('Cannot read time.txt')

def check_answers(file, n=10):
    try:
        with open(file) as f:
            d = f.read().strip()
            if len(d) < n:
                raise AssertionError('%s does not seem to contain enough text' % file)
    except IOError:
        raise AssertionError('Cannot read %s' % file)


##################################################################
# Controllers
#

__all__ += ["QEMU", "GDBClient"]

class QEMU(object):
    _GDBPORT = None

    def __init__(self, *make_args):
        # Check that QEMU is not currently running
        try:
            GDBClient(self.get_gdb_port(), timeout=0).close()
        except socket.error:
            pass
        else:
            print("""\
GDB stub found on port %d.
QEMU appears to already be running.  Please exit it if possible or use
'killall qemu' or 'killall qemu.real'.""" % self.get_gdb_port(), file=sys.stderr)
            sys.exit(1)

        if options.verbose:
            show_command(("make",) + make_args)
        cmd = ("make", "-s", "--no-print-directory") + make_args
        self.proc = Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT,
                          stdin=subprocess.PIPE)
        # Accumulated output as a string
        self.output = ""
        # Accumulated output as a bytearray
        self.outbytes = bytearray()
        self.on_output = []

    @staticmethod
    def get_gdb_port():
        if QEMU._GDBPORT is None:
            p = Popen(["make", "-s", "--no-print-directory", "print-gdbport"],
                      stdout=subprocess.PIPE)
            (out, _) = p.communicate()
            if p.returncode:
                raise RuntimeError(
                    "Failed to get gdbport: make exited with %d" %
                    p.returncode)
            QEMU._GDBPORT = int(out)
        return QEMU._GDBPORT

    def fileno(self):
        if self.proc:
            return self.proc.stdout.fileno()

    def handle_read(self):
        buf = os.read(self.proc.stdout.fileno(), 4096)
        self.outbytes.extend(buf)
        self.output = self.outbytes.decode("utf-8", "replace")
        for callback in self.on_output:
            callback(buf)
        if buf == b"":
            self.wait()
            return

    def write(self, buf):
        if isinstance(buf, str):
            buf = buf.encode('utf-8')
        self.proc.stdin.write(buf)
        self.proc.stdin.flush()

    def wait(self):
        if self.proc:
            self.proc.wait()
            self.proc = None

    def kill(self):
        if self.proc:
            self.proc.terminate()

class GDBClient(object):
    def __init__(self, port, timeout=15):
        start = time.time()
        while True:
            self.sock = socket.socket()
            try:
                self.sock.settimeout(1)
                self.sock.connect(("localhost", port))
                break
            except socket.error:
                if time.time() >= start + timeout:
                    raise
        self.__buf = ""

    def fileno(self):
        if self.sock:
            return self.sock.fileno()

    def handle_read(self):
        try:
            data = self.sock.recv(4096).decode("ascii", "replace")
        except socket.error:
            data = ""
        if data == "":
            self.sock.close()
            self.sock = None
            return
        self.__buf += data

        while True:
            m = re.search(r"\$([^#]*)#[0-9a-zA-Z]{2}", self.__buf)
            if not m:
                break
            pkt = m.group(1)
            self.__buf = self.__buf[m.end():]

            if pkt.startswith("T05"):
                # Breakpoint
                raise TerminateTest

    def __send(self, cmd):
        packet = "$%s#%02x" % (cmd, sum(map(ord, cmd)) % 256)
        self.sock.sendall(packet.encode("ascii"))

    def __send_break(self):
        self.sock.sendall(b"\x03")

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def cont(self):
        self.__send("c")

    def breakpoint(self, addr):
        self.__send("Z1,%x,1" % addr)


##################################################################
# QEMU test runner
#

__all__ += ["TerminateTest", "Runner"]

class TerminateTest(Exception):
    pass

class Runner():
    def __init__(self, *default_monitors):
        self.__default_monitors = default_monitors

    def run_qemu(self, *monitors, **kw):
        """Run a QEMU-based test.  monitors should functions that will
        be called with this Runner instance once QEMU and GDB are
        started.  Typically, they should register callbacks that throw
        TerminateTest when stop events occur.  The target_base
        argument gives the make target to run.  The make_args argument
        should be a list of additional arguments to pass to make.  The
        timeout argument bounds how long to run before returning."""

        def run_qemu_kw(target_base="qemu", make_args=[], timeout=40):
            return target_base, make_args, timeout
        target_base, make_args, timeout = run_qemu_kw(**kw)

        # Start QEMU
        pre_make()
        self.qemu = QEMU(target_base + "-gdb", *make_args)
        self.gdb = None

        try:
            # Wait for QEMU to start or make to fail.  This will set
            # self.gdb if QEMU starts.
            self.qemu.on_output = [self.__monitor_start]
            self.__react([self.qemu], timeout=90)
            self.qemu.on_output = []
            if self.gdb is None:
                print("Failed to connect to QEMU; output:")
                print(self.qemu.output)
                sys.exit(1)
            post_make()

            # QEMU and GDB are up
            self.reactors = [self.qemu, self.gdb]

            # Start monitoring
            for m in self.__default_monitors + monitors:
                m(self)

            # Run and react
            self.gdb.cont()
            self.__react(self.reactors, timeout)
        finally:
            # Shutdown QEMU
            try:
                if self.gdb is None:
                    sys.exit(1)
                self.qemu.kill()
                self.__react(self.reactors, 5)
                self.gdb.close()
                self.qemu.wait()
            except:
                print("""\
Failed to shutdown QEMU.  You might need to 'killall qemu' or
'killall qemu.real'.
""")
                raise

    def __monitor_start(self, output):
        if b"\n" in output:
            try:
                self.gdb = GDBClient(self.qemu.get_gdb_port(), timeout=2)
                raise TerminateTest
            except socket.error:
                pass
        if not len(output):
            raise TerminateTest

    def __react(self, reactors, timeout):
        deadline = time.time() + timeout
        try:
            while True:
                timeleft = deadline - time.time()
                if timeleft < 0:
                    sys.stdout.write("Timeout! ")
                    sys.stdout.flush()
                    return

                rset = [r for r in reactors if r.fileno() is not None]
                if not rset:
                    return

                rset, _, _ = select.select(rset, [], [], timeleft)
                for reactor in rset:
                    reactor.handle_read()
        except TerminateTest:
            pass

    def user_test(self, binary, *monitors, **kw):
        """Run a user test using the specified binary.  Monitors and
        keyword arguments are as for run_qemu.  This runs on a disk
        snapshot unless the keyword argument 'snapshot' is False."""

        maybe_unlink("obj/kern/init.o", "obj/kern/kernel")
        if kw.pop("snapshot", True):
            kw.setdefault("make_args", []).append("QEMUEXTRA+=-snapshot")
        self.run_qemu(target_base="run-%s" % binary, *monitors, **kw)

    def match(self, *args, **kwargs):
        """Shortcut to call assert_lines_match on the most recent QEMU
        output."""

        assert_lines_match(self.qemu.output, *args, **kwargs)

##################################################################
# Monitors
#

__all__ += ["save", "stop_breakpoint", "call_on_line", "stop_on_line", "shell_script",
            "parse_script"]

def save(path):
    """Return a monitor that writes QEMU's output to path.  If the
    test fails, copy the output to path.test-name."""

    def setup_save(runner):
        f.seek(0)
        f.truncate()
        runner.qemu.on_output.append(f.write)
        get_current_test().on_finish.append(save_on_finish)

    def save_on_finish(fail):
        f.flush()
        save_path = path + "." + get_current_test().__name__[5:]
        if fail:
            shutil.copyfile(path, save_path)
            print("    QEMU output saved to %s" % save_path)
        elif os.path.exists(save_path):
            os.unlink(save_path)
            print("    (Old %s failure log removed)" % save_path)

    f = open(path, "wb")
    return setup_save

def stop_breakpoint(addr):
    """Returns a monitor that stops when addr is reached.  addr may be
    a number or the name of a symbol."""

    def setup_breakpoint(runner):
        if isinstance(addr, str):
            addrs = [int(sym[:16], 16) for sym in open("kernel/kernel.sym")
                     if sym[17:].strip() == addr]
            assert len(addrs), "Symbol %s not found" % addr
            runner.gdb.breakpoint(addrs[0])
        else:
            runner.gdb.breakpoint(addr)
    return setup_breakpoint

def call_on_line(regexp, callback):
    """Returns a monitor that calls 'callback' when QEMU prints a line
    matching 'regexp'."""

    def setup_call_on_line(runner):
        buf = bytearray()
        def handle_output(output):
            buf.extend(output)
            while b"\n" in buf:
                line, buf[:] = buf.split(b"\n", 1)
                line = line.decode("utf-8", "replace")
                if re.match(regexp, line):
                    callback(line)
        runner.qemu.on_output.append(handle_output)
    return setup_call_on_line

def stop_on_line(regexp):
    """Returns a monitor that stops when QEMU prints a line matching
    'regexp'."""

    def stop(line):
        raise TerminateTest
    return call_on_line(regexp, stop)

def shell_script(script, terminate_match=None):
    """Returns a monitor that plays the script, and stops when the script is
    done executing."""

    def setup_call_on_line(runner):
        class context:
            n = 0
            buf = bytearray()
        def handle_output(output):
            context.buf.extend(output)
            if terminate_match is not None:
                if re.match(terminate_match, context.buf.decode('utf-8', 'replace')):
                    raise TerminateTest
            if b'$ ' in context.buf:
                context.buf = bytearray()
                if context.n < len(script):
                    runner.qemu.write(script[context.n])
                    runner.qemu.write('\n')
                    context.n += 1
                else:
                    if terminate_match is None:
                        raise TerminateTest
        runner.qemu.on_output.append(handle_output)
    return setup_call_on_line

def parse_script(expects: str):
    clean_expects = [s.strip() for s in expects.strip().splitlines()]
    script = []
    exps = []
    isregs = []
    for line in clean_expects:
        if line[:2] == '$ ':
            script.append(line[2:])
            exps.append(line)
            isregs.append(False)
        elif line[:1] == '^':
            exps.append(line + ('' if line[-1:] == '$' else '$'))
            isregs.append(True)
        else:
            exps.append(line)
            isregs.append(False)
    return script, exps, isregs