using System;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;

namespace server
{
    public class server
    {

        private string positions = "";
        // Declare a two dimensional array 
        // users allowed 10
        private static int maxSlots = 11;
        private string[,] posArray = new string[maxSlots + 1, 1];
        X509Certificate serverCertificate = new X509Certificate2("ssl.p12", "KeyPass");

        ManualResetEvent tcpClientConnected = new ManualResetEvent(false);

        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client.
            // The client signals the end of the message using the
            // "" marker.
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                bytes = sslStream.ReadByte();

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char znak = (char)bytes;
                messageData.Append(znak);
                // Check for EOF or an empty message.
                if (messageData.ToString().IndexOf("") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }

        void ProcessIncomingData(object obj)
        {
            SslStream sslStream = (SslStream)obj;
            //string ip = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

            //Console.WriteLine("Client IP : " + ip);


            string sb = "";
            int i = -1;
            try
            {
                while (true)
                {
                    int j = 10;
                    //Console.WriteLine((char)j);
                    while ((i = sslStream.ReadByte()) != 10)
                    {
                        sb = sb + (char)i;
                       // Console.WriteLine("Stream in char " +  i);
                        if (i == -1) break;
                    }
                    Console.WriteLine("Client " + sb);
                    byte[] messsage = Encoding.UTF8.GetBytes("Helloclient" + (char)j);
                    // Send hello message to the server.
                    sslStream.Write(messsage);
                    sslStream.Flush();

                }

            }
            catch (Exception e) { }

        }

        void ProcessIncomingConnection(IAsyncResult ar)
        {
            TcpListener listener = (TcpListener)ar.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(ar);
            SslStream sslStream = new SslStream(client.GetStream(), false);
            try
            {
                
                sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls, true);
                //DisplayCertificateInformation(sslStream);
            }catch(Exception e){
                Console.WriteLine("Client no ssl" + client);
            client.Close();
            }

            
            
            ThreadPool.QueueUserWorkItem(ProcessIncomingData, sslStream);
            tcpClientConnected.Set();
        }

        public void start()
        {
            IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8080);
            TcpListener listener = new TcpListener(endpoint);
            listener.Start();

            while (true)
            {
                tcpClientConnected.Reset();
                listener.BeginAcceptTcpClient(new AsyncCallback(ProcessIncomingConnection), listener);
                tcpClientConnected.WaitOne();
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("Multi user server. Recive save and send data to clients max 10 accounts.");
            //DateTime.Now.ToLongTimeString()
            Console.WriteLine(DateTime.Now + " Waiting for connections....");
            try
            {
                server s = new server();
                s.start();
            }
            catch (Exception e) { }
        }
    }
}
