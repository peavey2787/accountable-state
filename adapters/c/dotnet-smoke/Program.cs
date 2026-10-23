// What a Unity (Mono/IL2CPP) script does: P/Invoke the C ABI, persist the blobs it is told to,
// and reopen from them. Run by scripts/capi-dotnet-smoke.* against the freshly built library.
using System.Runtime.InteropServices;
using System.Text;

static class Native
{
    const string Lib = "gv_capi";

    [StructLayout(LayoutKind.Sequential)]
    public struct Buffer { public IntPtr Ptr; public UIntPtr Len; public UIntPtr Cap; }

    [DllImport(Lib)] public static extern int gv_queue_open(byte[] stored, UIntPtr storedLen, byte[] witnesses, UIntPtr witnessesLen, ulong now, ulong outboxLimit, out IntPtr queue);
    [DllImport(Lib)] public static extern void gv_queue_free(IntPtr queue);
    [DllImport(Lib)] public static extern int gv_queue_submit(IntPtr queue, ushort family, byte[] matchId, byte[] payload, UIntPtr payloadLen, byte priority, ulong deadline, ulong now, byte[] jobOut);
    [DllImport(Lib)] public static extern int gv_queue_step(IntPtr queue, ulong now, out UIntPtr done);
    [DllImport(Lib)] public static extern int gv_queue_job_state(IntPtr queue, byte[] job, out byte state);
    [DllImport(Lib)] public static extern int gv_queue_events_after(IntPtr queue, ulong cursor, UIntPtr limit, out Buffer buf);
    [DllImport(Lib)] public static extern int gv_queue_take_writes(IntPtr queue, out Buffer buf);
    [DllImport(Lib)] public static extern void gv_buffer_free(Buffer buf);
}

static class Smoke
{
    const int Ok = 0, Failed = 7;
    const ushort SignedInputs = 1;

    static void Check(bool ok, string what)
    {
        if (!ok) { Console.Error.WriteLine("FAIL: " + what); Environment.Exit(1); }
    }

    static byte[] Take(Native.Buffer b)
    {
        var bytes = new byte[(int)b.Len];
        if (bytes.Length > 0) Marshal.Copy(b.Ptr, bytes, 0, bytes.Length);
        Native.gv_buffer_free(b);
        return bytes;
    }

    static byte[] Pack(params byte[][] items)
    {
        var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes((uint)items.Length));
        foreach (var i in items) { ms.Write(BitConverter.GetBytes((uint)i.Length)); ms.Write(i); }
        return ms.ToArray();
    }

    static IntPtr Open(byte[] stored)
    {
        Check(Native.gv_queue_open(stored, (UIntPtr)stored.Length, new byte[0], UIntPtr.Zero, 1000, 1 << 20, out var q) == Ok, "open");
        return q;
    }

    static byte State(IntPtr q, byte[] job)
    {
        Check(Native.gv_queue_job_state(q, job, out var s) == Ok, "job_state");
        return s;
    }

    static int Main()
    {
        var match = Enumerable.Repeat((byte)7, 32).ToArray();
        var junk = Pack(new byte[] { 1, 2, 3 });
        var q = Open(new byte[0]);
        var job = new byte[32];
        Check(Native.gv_queue_submit(q, SignedInputs, match, junk, (UIntPtr)junk.Length, 1, ulong.MaxValue, 1000, job) == Ok, "submit");
        Check(State(q, job) == 0, "pending after submit");
        Check(Native.gv_queue_step(q, 1001, out var done) == Ok && (int)done == 1, "step verified one job");
        Check(State(q, job) == Failed, "unusable evidence is Failed, never a conviction");

        Check(Native.gv_queue_events_after(q, 0, (UIntPtr)10, out var ev) == Ok, "events");
        var json = Encoding.UTF8.GetString(Take(ev));
        Check(json.Contains("\"gap\":false"), "events json: " + json);

        Check(Native.gv_queue_take_writes(q, out var w) == Ok, "take_writes");
        var stored = Take(w);
        Check(stored.Length > 4, "the host was told to store something");
        Native.gv_queue_free(q);

        var again = Open(stored);
        Check(State(again, job) == Failed, "the verdict survived a restart");
        Check(Native.gv_queue_job_state(again, new byte[32], out _) == 3, "unknown job is NotFound");
        Native.gv_queue_free(again);
        Console.WriteLine("PASS: Unity-style P/Invoke of the proof queue C ABI (open, submit, step, events, persist, reopen)");
        return 0;
    }
}
