using NLog;
using NoesisApp;
using NSec.Cryptography;
using System.Net;
using System.Net.Quic;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;

namespace LBOTLBOT
{
    internal static class AssemblyTickler
    {
        public static void TickleAll()
        {
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                TickleAssembly(asm);
            }
        }

        private static void TickleAssembly(Assembly asm)
        {
            Type[] types;
            try
            {
                types = asm.GetTypes().Where(t => t != null).Select(t => t).ToArray();
            } catch (ReflectionTypeLoadException ex)
            {
                types = ex.Types.Where(t => t != null).Select(t => t!).ToArray();
            }

            foreach (var t in types)
            {
                TickleType(t);
            }
        }

        private static void TickleType(Type t)
        {
            _ = t.FullName;
            _ = t.AssemblyQualifiedName;

            if (!t.IsAbstract && t.GetConstructor(Type.EmptyTypes) != null)
            {
                try
                {
                    Activator.CreateInstance(t);
                }
                catch { }
            }

            foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                _ = m.Name;
            }

            foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                _ = f.Name;
            }
        }
    }

    internal static class GenericBomb
    {
        public static void Instantiate()
        {
            Touch<byte>();
            Touch<sbyte>();
            Touch<ushort>();
            Touch<short>();
            Touch<uint>();
            Touch<int>();
            Touch<ulong>();
            Touch<long>();
            Touch<string>();
            Touch<byte[]>();
            Touch<object>();
        }

        private static void Touch<T>()
        {
            _ = typeof(System.Collections.Generic.List<T>);
            _ = typeof(System.Threading.Channels.Channel<T>);
            _ = typeof(System.Linq.Enumerable);

            try
            {
                var list = new System.Collections.Generic.List<T>();
                list.Add(default!);
            }
            catch { }
        }
    }

    internal static class NetRoot
    {
        public static void Touch()
        {
            _ = Dns.GetHostName();

            using var client = new HttpClient();
            _ = client.DefaultRequestHeaders;

            using var sock = new Socket(System.Net.Sockets.AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _ = QuicListener.ListenAsync(default!);
            _ = QuicConnection.ConnectAsync(default!);
        }
    }
    
    internal static class CryptoRoot
    {
        public static void Touch()
        {
            using var sha = SHA256.Create();
            sha.ComputeHash(new byte[32]);

            var alg = SignatureAlgorithm.Ed25519;
            var kp = Key.Create(alg);
            _ = kp.Export(KeyBlobFormat.RawPrivateKey);
        }
    }

    internal static class LoggingRoot
    {
        public static void Touch()
        {
            using var hub = new Sentry.SentryClient(new SentryOptions() { Dsn = "https://example.invalid/1" });
            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Hello NLog");
        }
    }

    internal class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            AssemblyTickler.TickleAll();
            GenericBomb.Instantiate();
            NetRoot.Touch();
            CryptoRoot.Touch();
            LoggingRoot.Touch();

            Console.WriteLine("Buh");
            GC.KeepAlive(typeof(Program));
        }
    }
}
