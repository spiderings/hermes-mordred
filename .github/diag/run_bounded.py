"""Run pytest in a child process with a hard deadline; on expiry kill the whole tree and print captured output."""
import os, subprocess, sys, time, pathlib
deadline = float(sys.argv[1]); args = sys.argv[2:]
out = pathlib.Path("diag-pytest-output.txt")
with out.open("wb") as fh:
    proc = subprocess.Popen([sys.executable, "-X", "faulthandler", "-m", "pytest", *args], stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    start = time.monotonic(); timed_out = False
    while proc.poll() is None:
        if time.monotonic() - start > deadline:
            timed_out = True
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=False)
            break
        time.sleep(1)
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        pass
print(f"=== bounded run: timed_out={timed_out} returncode={proc.returncode} elapsed={time.monotonic()-start:.0f}s")
data = out.read_bytes()
print(f"=== captured {len(data)} bytes (tail)")
sys.stdout.write(data[-60000:].decode("utf-8", "replace"))
if timed_out:
    print("=== remaining python/hermes processes:")
    subprocess.run(["tasklist", "/FI", "IMAGENAME eq python.exe"], check=False)
sys.exit(2 if timed_out else proc.returncode)
