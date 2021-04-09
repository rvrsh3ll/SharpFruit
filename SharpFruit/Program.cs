using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Net;
using NDesk.Options;
using LukeSkywalker.IPNetwork;
using System.Threading.Tasks;

namespace SharpFruit
{

    public class SharpFruit
    {
        public static void Main(string[] args)
        { 
            string useragent = null;
            string cidr = null;
            int port = 80;
            bool ssl = false;
            bool showhelp = false;
            bool outfile = false;
            var opts = new OptionSet()
            {

                { "cidr=", " --cidr 192.168.1.0/24", v => cidr = v },
                { "port=", " --port 8080", (int v) => port = v },
                { "ssl", " --ssl+", v => ssl = v != null },
                { "useragent=", " --useragent 'Googlebot'", v => useragent = v ?? "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident / 7.0; AS; rv: 11.0) like Gecko"},
                { "outfile", " --outfile+", v => outfile = v != null },
                { "h|?|help",  "Show available options", v => showhelp = v != null },
            };

            try
            {
                opts.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("\r\n       _________.__                      ___________            .__  __   ");
            Console.WriteLine("     /   _____/|  |__ _____ _____________\\_   _____/______ __ __|__|/  |_ ");
            Console.WriteLine("     \\_____  \\ |  |  \\\\__  \\\\_  __ \\____ \\|    __) \\_  __ \\  |  \\  \\   __\\");
            Console.WriteLine("     /        \\|   Y  \\/ __ \\|  | \\/  |_> >     \\   |  | \\/  |  /  ||  | ");
            Console.WriteLine("    /_______  /|___|  (____  /__|  |   __/\\___  /   |__|  |____/|__||__|");
            Console.WriteLine("            \\/      \\/     \\/      |__|       \\/\r\n");
            Console.WriteLine("  v1.0.0\r\n");


            if (showhelp)
            {
                Console.WriteLine("RTFM");
                opts.WriteOptionDescriptions(Console.Out);
                Console.WriteLine("[*] Example: SharpFruit.exe --cidr 192.168.1.0/24 --port 9443 --ssl+ --outfile+");
                return;
            }

            // Parse CIDR
            IPNetwork ipn = IPNetwork.Parse(cidr);
            IPAddressCollection ips = IPNetwork.ListIPAddress(ipn);

            // List of potentially vulnerable URI's
            List<string> uris = new List<string>();
            uris.Add("/manager/html");
            uris.Add("/jmx-console/");
            uris.Add("/web-console/ServerInfo.jsp");
            uris.Add("/invoker/JMXInvokerServlet");
            uris.Add("/system/console");
            uris.Add("/axis2/axis2-admin/");
            uris.Add("/wp-admin");
            uris.Add("/workorder/FileDownload.jsp");
            uris.Add("/ibm/console/logon.jsp?action=OK");
            uris.Add("/data/login");
            uris.Add("/script/");
            uris.Add("/opennms/");
            uris.Add("/vsphere-client/");
            uris.Add("/vsphere-client/?csp");
            uris.Add("/exchange/servlet/ADSHACluster");
            uris.Add("/securityRealm/user/admin/");

            // Declare protocol variable
            string protocol = "";
            if (outfile)
            {
                DualOut.Init();
            }

            // Parallel ForEach to iterate over IP's from CIDR block
            Parallel.ForEach(ips, ip =>
            {
                foreach (string uri in uris)
                {
                    if (port == 443)
                    {
                        ssl = true;
                    }
                    // Set the protocol
                    if (ssl)
                    {
                        protocol = "https";
                    }
                    else
                    {
                        protocol = "http";
                    }
                    string target = protocol + "://" + ip + ":" + port + uri;

                    HttpWebResponse response = null;
                    try
                    {
                        
                        // Initialize our request and set options
                        HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(target);
                        request.Accept = "*/*";
                        request.Timeout = 600;
                        request.Method = "GET";
                        request.UserAgent = useragent;
                        request.KeepAlive = false;

                        // Disable SSL Certificate errors
                        request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                        
                        response = (HttpWebResponse)request.GetResponse();

                        if ((int)response.StatusCode == (int)200)
                        {
                            Console.WriteLine("[*] Found " + target);
                        }
                        else
                        {
                            Console.WriteLine(uri + " - Returned" + (int)response.StatusCode + "\r\n");
                        }
                    }
                    catch (WebException e)
                    {
                        if (e.Status == WebExceptionStatus.ProtocolError)
                        {
                            response = (HttpWebResponse)e.Response;
                            if ((int)response.StatusCode == (int)401)
                            {
                                Console.WriteLine(target + " - Returned a 401 which, indicates possible basic auth.\r\n");
                            }
                            else
                            {
                                continue;
                            }
                        }
                        else
                        {
                            continue;
                        }
                    }
                    finally
                    {
                        if (response != null)
                        {
                            response.Close();
                        }
                    }
                }
            });
        }
    }
    public static class DualOut
    {
        private static TextWriter _current;
        private class OutputWriter : TextWriter
        {
            public override Encoding Encoding
            {
                get
                {
                    return _current.Encoding;
                }
            }
            public override void WriteLine(string value)
            {
                _current.WriteLine(value);
                File.WriteAllLines("Outfile.txt", new string[] { value });
            }
        }
        public static void Init()
        {
            
            _current = Console.Out;
            Console.SetOut(new OutputWriter());
        }
    }
}
