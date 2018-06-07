using System;
using System.CodeDom;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;

namespace RsaServer
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string acquiredHash;
        private RSACryptoServiceProvider decr;
        private readonly string IP_ADDRESS = "127.0.0.1";
        private readonly int KEYS_BITS = 3072;
        private readonly int PORT = 8888;
        private NetworkStream stream;

        public MainWindow()
        {
            InitializeComponent();
        }

        private RSACryptoServiceProvider Keys { get; set; }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            var localAddr = IPAddress.Parse(IP_ADDRESS);
            var server = new TcpListener(localAddr, PORT);
            server.Start();
            while (true)
                if (server.Pending())
                {
                    rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Client connected...")));
                    stream = server.AcceptTcpClient().GetStream();
                    ExchangeKeys();
                    break;
                }
            //ExchangeHash();
            var receiveThread = new Thread(ReceiveMessage);
            receiveThread.Start();
        }

        private void ExchangeKeys()
        {
            rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Generating RSA public and private keys...")));
            Keys = new RSACryptoServiceProvider(KEYS_BITS);
            var publicKey = Keys.ToXmlString(false);
            rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Sending public key to client...")));
            stream.Write(Encoding.Unicode.GetBytes(publicKey), 0, Encoding.Unicode.GetBytes(publicKey).Length);
        }

        private void ReceiveMessage()
        {
            while (true)
            try
            {
                ExchangeHash();
                var data = new byte[384];
                var builder = new StringBuilder();
                var bytes = 0;
                string message;
                do
                {
                    bytes = stream.Read(data, 0, data.Length);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                } while (stream.DataAvailable);

                if (acquiredHash == CreateMD5(data))
                {
                decr = new RSACryptoServiceProvider();
                decr.FromXmlString(Keys.ToXmlString(true)); // load our private key
                var decrData = decr.Decrypt(data, true);
                message = Encoding.Unicode.GetString(decrData);
                Dispatcher.Invoke(() =>
                {
                    rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Message received: " + message)));
                });
                }
                else
                {
                    throw new Exception("Hashes do not match");
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    rtbStatus.Document.Blocks.Add(new Paragraph(new Run(ex.Message))); //ex.Message
                    //rtbStatus.Document.Blocks.Add(new Paragraph(new Run(Keys.ToXmlString(false))));
                });
            }
        }

        public static string CreateMD5(byte[] input)
        {
            // Use input string to calculate MD5 hash
            using (MD5 hashMD5 = MD5.Create())
            {
                byte[] hashBytes = hashMD5.ComputeHash(input);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }

        private void ExchangeHash()
        {
            var builder = new StringBuilder();
            var bytes = 0;
            int i = 0;
            var data = new byte[384];
            do
            {
                bytes = stream.Read(data, 0, data.Length);
                builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                i++;
            } while (i == 2); //stream.DataAvailable
            stream.Flush();
            acquiredHash = builder.ToString();
        }
    }
}