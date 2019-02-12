using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace Versleutelen
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private RSACryptoServiceProvider rsa;
        private UnicodeEncoding byteConverter;
        private CspParameters csp;
        private static Random random;
        private DateTime dateTime;
        private string filePath;
        private int keyMaxValue;

        public MainWindow()
        {
            InitializeComponent();

            // 1 character = 8 bits
            keyMaxValue = 256;
            labelKeyLength.Content = "Length Key: (Max " + keyMaxValue.ToString() + ")";
        }

        // Clears textbox and calls ASREncryption method
        private void ButtonDecryption_Click(object sender, RoutedEventArgs e)
        {
            //// Create an instance of the RSA algorithm class
            //rsa = new RSACryptoServiceProvider();
            //// Get the private key
            //string privateKey = rsa.ToXmlString(true); // true to get the private key

            //textboxLeft.Clear();
            //textboxPrivateKey.Clear();
            //textboxPrivateKey.Text = privateKey;
            //textboxLeft.AppendText(DecryptData(privateKey, textboxRight.Text));

            textboxLeft.Clear();
            CheckInput(textboxRight.Text, textboxPublicKey.Text, textboxRandomKeyLength.Text, "decryption");

            //textboxLeft.Text = Encoding.Unicode.GetString(Convert.FromBase64String(textboxRight.Text));
        }

        // Clears textbox and calls ASREncryption method
        private void ButtonEncryption_Click(object sender, RoutedEventArgs e)
        {
            //// Create an instance of the RSA algorithm class
            ///
            //rsa = new RSACryptoServiceProvider();
            //// Get the public key
            //string publicKey = rsa.ToXmlString(false); // false to get the public key

            //textboxRight.Clear();
            //textboxPublicKey.Clear();
            //textboxPublicKey.Text = publicKey;
            //textboxRight.AppendText(EncryptData(publicKey, textboxLeft.Text));

            textboxRight.Clear();
            CheckInput(textboxLeft.Text, textboxPublicKey.Text, textboxRandomKeyLength.Text, "encryption");

            //textboxRight.Text = Convert.ToBase64String(Encoding.Unicode.GetBytes(textboxLeft.Text));
        }

        private void ButtonExportDecryptedFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog("textboxLeft");
        }

        private void ButtonExportEncryptedFile_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog("textboxRight");
        }

        private void ButtonImportDecryptedFile_Click(object sender, RoutedEventArgs e)
        {
            textboxLeft.Clear();
            OpenFileDialog("textboxLeft");
        }

        private void ButtonImportEncryptedFile_Click(object sender, RoutedEventArgs e)
        {
            textboxRight.Clear();
            OpenFileDialog("textboxRight");
        }

        private void CheckInput(string textInput, string key, string keyLength, string state)
        {
            if (textInput != "")
            {
                if (checkboxRandomKey.IsChecked == true)
                {
                    textboxPublicKey.Clear();
                    if (int.TryParse(textboxRandomKeyLength.Text, out int resultLength))
                    {
                        if (resultLength > 0 && resultLength <= keyMaxValue)
                        {
                            key = GetRandomKey(resultLength);
                            RSAEncryption(textInput, key, true, keyLength, state);
                        }
                        else
                        {
                            MessageBox.Show($"Key Lenght must be between 0 and {keyMaxValue + 1}");
                            //MessageBox.Show("Key Lenght must be between 0 and " + (keyMaxValue + 1).ToString());
                        }
                    }
                    else
                    {
                        MessageBox.Show("Key Lenght must contain only numbers");
                    }
                }
                else
                {
                    if (textboxPublicKey.Text != "")
                    {
                        if (key.Length > 0 && key.Length <= keyMaxValue)
                        {
                            RSAEncryption(textInput, key, false, keyLength, state);
                        }
                        else
                        {
                            MessageBox.Show($"Key Lenght must be between 0 and {keyMaxValue + 1}");
                        }
                    }
                    else
                    {
                        MessageBox.Show("Encryption Key  must be entered");
                    }
                }
            }
            else
            {
                MessageBox.Show("Text must be entered");
            }
        }

        private string DecryptData(string privateKey, string text)
        {
            // read the encrypted bytes from the file in the textbox
            string[] hexArray = text.Split('-');
            byte[] dataToDecrypt = new byte[hexArray.Length];
            for (int i = 0; i < hexArray.Length; i++)
            {
                dataToDecrypt[i] = Convert.ToByte(hexArray[i], 16);
            }
            //byte[] bytes = Array.ConvertAll(hexArray, x => Convert.ToByte(x, 16));

            try
            {
                // Create an array to store the decrypted data in it
                byte[] decryptedData;
                using (rsa = new RSACryptoServiceProvider())
                {
                    // Set the private key of the algorithm
                    rsa.FromXmlString(privateKey);
                    decryptedData = rsa.Decrypt(dataToDecrypt, false);
                }
                // Get the string value from the decryptedData byte array
                byteConverter = new UnicodeEncoding();
                return byteConverter.GetString(decryptedData);
            }
            catch (CryptographicException Cex)
            {
                MessageBox.Show(Cex.ToString());
                return null;
            }
        }

        private string EncryptData(string publicKey, string text)
        {
            // Convert the text to an byte array
            byteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = byteConverter.GetBytes(text);

            try
            {
                // Create a byte array to store the encrypted data in it
                byte[] encryptedData;
                using (rsa = new RSACryptoServiceProvider())
                {
                    // Set the rsa pulic key
                    rsa.FromXmlString(publicKey);

                    // Encrypt the data and store it in the encyptedData Array
                    encryptedData = rsa.Encrypt(dataToEncrypt, false);
                }
                // Save the encypted data array into a file
                //File.WriteAllBytes(fileName, encryptedData);

                // Displays encrypted data in textbox
                string encryptedText = BitConverter.ToString(encryptedData);
                //textboxRight.AppendText(encrypted);
                return encryptedText;
            }
            catch (CryptographicException Cex)
            {
                MessageBox.Show(Cex.ToString());
                return null;
            }
        }

        private string GetRandomKey(int keyLength)
        {
            //string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()<>?{}";

            //return new string(Enumerable.Repeat(characters, keyLength).Select(s => s[random.Next(s.Length)]).ToArray());

            
            string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()<>?{}";
            char[] stringChars = new char[keyLength];
            random = new Random();
            string stringResult;

            // Loops through every index in stringChars, fills every index with random characters selected from characters string
            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = characters[random.Next(characters.Length)];
            }
            
            return stringResult = new String(stringChars);
        }

        private void OpenFileDialog(string textboxName)
        {
            // Opens open file dialog window in the Documents directory
            OpenFileDialog openFileDialog = new OpenFileDialog();
            //openFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            filePath = System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(System.IO.Directory.GetCurrentDirectory()));
            filePath += "\\Documents\\";
            openFileDialog.InitialDirectory = filePath;
            openFileDialog.Filter = "Text Files | *.txt";

            // Tries to read from the selected text file
            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    using (StreamReader inStreamReader = File.OpenText(openFileDialog.FileName))
                    {
                        string importedFile = inStreamReader.ReadToEnd();
                        if (textboxName == "textboxLeft")
                        {
                            textboxLeft.AppendText(importedFile);
                        }
                        else
                        {
                            textboxRight.AppendText(importedFile);
                        }
                    }
                }
                catch (IOException IOex)
                {
                    MessageBox.Show(IOex.ToString());
                }
                catch (OutOfMemoryException OOMex)
                {
                    MessageBox.Show(OOMex.Message);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
                //filePath = openFileDialog.FileName;
            }
        }

        private void RSAEncryption(string textInput, string key, bool keyIsSet, string keyLength, string state)
        {
            csp = new CspParameters();

            if (!keyIsSet)
            {
                // Sets key
                csp.KeyContainerName = key;
            }

            rsa = new RSACryptoServiceProvider(csp);
            //string publicKey = rsa.ToXmlString(false); // false to get the public key
            //string privateKey = rsa.ToXmlString(true); // true to get the private key
            //textboxPublicKey.Text = publicKey;
            //textboxPrivateKey.Text = privateKey;
            rsa.PersistKeyInCsp = true;

            // Checks which state is selected
            if (state == "encryption")
            {
                // Saves texts in byte Array, Encrypts text in UTF-* format
                byte[] textBytes = Encoding.UTF8.GetBytes(textInput);
                byte[] bytes = rsa.Encrypt(textBytes, true);

                string encrypted = BitConverter.ToString(bytes);
                textboxRight.AppendText(encrypted);
                textboxPublicKey.Text = key;
            }
            else if (state == "decryption")
            {
                // Tries to decrypt encoded text, by checking the key
                try
                {
                    // Saves encoded text in string array converts it to a byte array, decrypts the
                    // bytes to text
                    string[] hexArray = textInput.Split('-');
                    byte[] arrayByte = new byte[hexArray.Length];

                    for (int i = 0; i < hexArray.Length; i++)
                    {
                        arrayByte[i] = Convert.ToByte(hexArray[i], 16);
                    }
                    byte[] textBytes = rsa.Decrypt(arrayByte, true);
                    //byte[] bytes = Array.ConvertAll(hexArray, x => Convert.ToByte(x, 16));
                    //byte[] textBytes = rsa.Decrypt(bytes, true);

                    string decrypted = Encoding.UTF8.GetString(textBytes);
                    textboxLeft.AppendText(decrypted);
                    textboxPublicKey.Text = key;
                }
                catch (CryptographicException Cex)
                {
                    MessageBox.Show("Incorrect encryption key entered. \n" + Cex.Message);
                }
            }
        }

        private void SaveFileDialog(string textboxName)
        {
            // sets current date and time as file name
            dateTime = DateTime.Now;
            string formattedDateTime = dateTime.ToString("ddMMyyyy_HHmmss");
            string fileName = "EncryptionFile_" + formattedDateTime + ".txt";
            //filePath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // Opens save file dialog window in the Documents directory
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            //saveFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            filePath = System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(System.IO.Directory.GetCurrentDirectory()));
            filePath += "\\Documents\\";
            saveFileDialog.InitialDirectory = filePath;
            saveFileDialog.Filter = "Text Files | *.txt";
            saveFileDialog.FileName = fileName;

            // Tries to write to the selected directory
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    using (StreamWriter outStreamWriter = File.CreateText(saveFileDialog.FileName))
                    {
                        if (textboxName == "textboxLeft")
                        {
                            outStreamWriter.WriteLine(textboxLeft.Text);
                        }
                        else
                        {
                            outStreamWriter.WriteLine(textboxRight.Text);
                        }
                    }
                }
                catch (IOException IOex)
                {
                    MessageBox.Show(IOex.Message);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
                //filePath = saveFileDialog.FileName;
            }
        }
    }
}