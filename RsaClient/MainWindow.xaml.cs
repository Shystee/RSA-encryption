using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Documents;

namespace RsaClient
{
    /// <summary>
    ///     Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string acquiredPublicKey;
        private RSACryptoServiceProvider enc;
        private readonly string IP_ADDRESS = "127.0.0.1";
        private int KEYS_BITS = 3072;
        private readonly int PORT = 8888;
        private NetworkStream stream;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            var client = new TcpClient();
            client.Connect(IP_ADDRESS, PORT);
            
            if (client.Connected)
            {
                rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Connection to server has been established...")));
                stream = client.GetStream();
                ExchangeKeys();
                rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Server public key: " + acquiredPublicKey)));
            }
            else
            {
                rtbStatus.Document.Blocks.Add(new Paragraph(new Run(
                    string.Format("Connection error, while trying to connect to {0} on {1}", IP_ADDRESS, PORT))));
            }
        }

        private void ExchangeKeys()
        {
            var builder = new StringBuilder();
            var bytes = 0;
            var data = new byte[1024];
            do
            {
                bytes = stream.Read(data, 0, data.Length);
                builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
            } while (stream.DataAvailable);

            rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Receiving server public key...")));
            acquiredPublicKey = builder.ToString();
        }

        private void SendMessage(string message)
        {
            rtbStatus.Document.Blocks.Add(new Paragraph(new Run("Message sent: " + txtMessage.Text)));
            var data = new byte[384];
            enc = new RSACryptoServiceProvider();
            enc.FromXmlString(acquiredPublicKey); // load acquired public key
            data = enc.Encrypt(Encoding.Unicode.GetBytes(message), true);
            SendHash(data);
            //rtbStatus.Document.Blocks.Add(new Paragraph(new Run(CreateMd5(data))));
            stream.Write(data, 0, data.Length);
        }

        private void btnSend_Click(object sender, RoutedEventArgs e)
        {
            SendMessage(txtMessage.Text);
        }

        private string CreateMd5(byte[] input)
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

        private void SendHash(byte[] input)
        {
            var hashMd5 = CreateMd5(input);
            stream.Write(Encoding.Unicode.GetBytes(hashMd5), 0, Encoding.Unicode.GetBytes(hashMd5).Length);
        }

        private void btnTest_Click(object sender, RoutedEventArgs e)
        {
            RSACryptoServiceProvider Keys = new RSACryptoServiceProvider(KEYS_BITS);
            acquiredPublicKey = Keys.ToXmlString(false);
        }
    }
}