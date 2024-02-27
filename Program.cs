using System.Security.Cryptography;
using System.Xml;
using System.Text;
using CommandLine;
using System;

class Program{
    //configurable sizes for pad data in bytes
    private static int messageLength = 192;
    private static int shuffleKeyLength = 32;
    private static int macNonceLength = 32;

    class MessageData{
        public byte[] MAC { get; set; }
        public byte[] Body { get; set; }
    }
    class PadData{
        public byte[] NonceBytes { get; set; }
        public byte[] ShuffleBytes { get; set; }
        public byte[] MixBytes { get; set; }
    }
    public class Options{
        [Option('g', "generatePad", HelpText = "Use a bin file to generate a directory of pad files.")]
        public bool GeneratePad { get; set; }

        [Option('e', "encrypt", HelpText = "Encrypt a plaintext message using the specified pad file.")]
        public bool Encrypt { get; set; }

        [Option('d', "decrypt", HelpText = "Decrypt an encrypted message using the specified pad file.")]
        public bool Decrypt { get; set; }

        [Option('b', "binPath", HelpText = "Path for the bin file for generating pad files.")]
        public string BinPath { get; set; }

        [Option('m', "messagePath", HelpText = "Path for the plaintext or encrypted message file.")]
        public string MessagePath { get; set; }

        [Option('p', "padPath", HelpText = "Path to the pad file.")]
        public string PadPath { get; set; }

        [Option('o', "outputPath", HelpText = "Path for the output files.")]
        public string OutputPath { get; set; }
    }

    public static void Main(string[] args){
        string mode = "";
        string binPath = "";
        string messagePath = "";
        string padPath = "";
        string outputPath = "";

        PadData padData = new PadData();
        byte[] plaintextMessage = new byte[messageLength];
        MessageData messageData = new MessageData();

        Parser.Default.ParseArguments<Options>(args).WithParsed(options =>{
            // Check if more than one main action flag (-g, -e, -d) is specified
            if ((options.GeneratePad ? 1 : 0) + (options.Encrypt ? 1 : 0) + (options.Decrypt ? 1 : 0) > 1){
                throw new ArgumentException("Error: Only one of -g, -e, -d flags can be used.");
            }

            //set mode based on flag used
            if (options.GeneratePad){
                mode = "generatePad";
            }else if (options.Encrypt){
                mode = "encrypt";
            }else if (options.Decrypt){
                mode = "decrypt";
            } else {
                throw new ArgumentException("Invalid mode selection.");
            }

            binPath = options.BinPath;
            messagePath = options.MessagePath;
            padPath = options.PadPath;
            outputPath = options.OutputPath;

        }).WithNotParsed(errors =>{
            Console.WriteLine("Error parsing command-line arguments:");
            foreach (var error in errors){
                Console.WriteLine(error);
            }
            Environment.Exit(1);
        });
        
        try{
            switch(mode){
                case "generatePad":
                    CreatePadbook(binPath, outputPath);
                    break;
                case "encrypt":
                    //read message from disk
                    plaintextMessage = Encoding.UTF8.GetBytes(File.ReadAllText(messagePath));
                    padData = ReadPadData(padPath);
    
                    //pad message
                    plaintextMessage = PadMessage(plaintextMessage);

                    //shuffle text
                    plaintextMessage = ShuffleUtility.Shuffle(padData.ShuffleBytes, plaintextMessage);

                    //encrypt text and generate hmac
                    byte[] cypherText = MixBytes(plaintextMessage, padData.MixBytes);
                    byte[] hmac = GenerateHMACSHA512(padData.NonceBytes, cypherText);
        
                    //write hmac and cypher text to disk
                    WriteMessageData(cypherText, hmac, outputPath);
                    break;
                case "decrypt":
                    //read cypher text and hmac from disk
                    messageData = ReadMessageData(messagePath);
                    padData = ReadPadData(padPath);

                    //verify if hmac is valid or invalid
                    if(VerifyHMACSHA512(padData.NonceBytes, messageData.Body, messageData.MAC)){
                        Console.WriteLine("HMAC is valid");
                    } else {
                        Console.WriteLine("HMAC is not valid");
                        throw new ArgumentException("HMAC invalid. Canceling decryption.");
                    }

                    //decrypt cypher text
                    byte[] decryptedMessage = MixBytes(messageData.Body, padData.MixBytes);

                    //unshuffle plaintext
                    decryptedMessage = ShuffleUtility.Unshuffle(padData.ShuffleBytes, decryptedMessage);

                    //write plaintext to disk
                    File.WriteAllText(outputPath, Encoding.UTF8.GetString(decryptedMessage));
                    break;
                default:
                    throw new ArgumentException("Invalid mode selection.");
            }
        }catch (Exception ex){
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    private static byte[] PadMessage(byte[] message){
        //message must be <= key length>
        if(message.Length >= messageLength){
            throw new ArgumentException("Message length exceeds key length");
        }

        try{
            Random random = new Random();
            //append random ascii char until message matches length of key
            while(message.Length < messageLength){
                Array.Resize(ref message, message.Length + 1);
                message[message.Length-1] = (byte)(char)random.Next(33, 127);
            }
            return message;
        }catch (Exception ex){
            Console.WriteLine($"Error while padding message: {ex.Message}");
            return null;
        }
    }
    private static byte[] MixBytes(byte[] messageBytes, byte[] padBytes){
        try{
            //message and key must be the same length
            if(messageBytes.Length != messageLength){
                throw new ArgumentException("Message length must equal key length");
            }

            byte[] result = new byte[messageLength];

            //xor each byte in message with bytes in pad
            for (int i = 0; i < messageLength; i++){
                result[i] = (byte)(messageBytes[i] ^ padBytes[i]); 
            }

            return result;
        }catch (Exception ex){
            Console.WriteLine($"Error mixing message and pad bytes: {ex.Message}");
            return null;
        }
    }
    private static byte[] GenerateHMACSHA512(byte[] key, byte[] data){
        try{
            //generate an HMAC for the given cypher text and nonce
            using (HMACSHA512 hmac = new HMACSHA512(key)){
                return hmac.ComputeHash(data);
            }
        }catch (Exception ex){
            Console.WriteLine($"Error generating HMAC: {ex.Message}");
            return null;
        }
    }
    private static bool VerifyHMACSHA512(byte[] key, byte[] data, byte[] expectedMac){
        try{
            //generate the HMAC for the recieved cypher text and nonce from pad
            byte[] actualMac = GenerateHMACSHA512(key, data);

            //check if hmac recieved matches what the hmac should be
            return CryptographicOperations.FixedTimeEquals(actualMac, expectedMac);
        }catch (Exception ex){
            Console.WriteLine($"Error verifying HMAC: {ex.Message}");
            return false;
        }
    }

    private static MessageData ReadMessageData(string messagePath){
        try{
            if(!File.Exists(messagePath)){
                throw new ArgumentException("File " + messagePath + "doesn't exist");
            }

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(messagePath);

            //read xml attributes and convert to byte[]
            XmlNode padNode = xmlDoc.SelectSingleNode("message");
            byte[] mac = Convert.FromBase64String(padNode.SelectSingleNode("mac").InnerText);
            byte[] body = Convert.FromBase64String(padNode.SelectSingleNode("body").InnerText);

            //return new MessageData instance with the read message data
            return new MessageData{
                MAC = mac,
                Body = body,
            };
        }catch (Exception ex){
            Console.WriteLine($"Error reading cypher text message XML file: {ex.Message}");
            return null;
        }
    }
    private static void WriteMessageData(byte[] bodyBytes, byte[] hmacBytes, string outputPath){
        try{
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.Encoding = Encoding.ASCII;

            //write message components to disk
            using (XmlWriter writer = XmlWriter.Create(outputPath, settings)){
                // Write XML declaration
                writer.WriteStartDocument();

                // Write root element <pad>
                writer.WriteStartElement("message");

                // Write mac element
                writer.WriteStartElement("mac");
                writer.WriteBase64(hmacBytes, 0, hmacBytes.Length);
                writer.WriteEndElement();

                // Write body element
                writer.WriteStartElement("body");
                writer.WriteBase64(bodyBytes, 0, bodyBytes.Length);
                writer.WriteEndElement();

                // Close root element </pad>
                 writer.WriteEndElement();

                // Close the document
                writer.WriteEndDocument();
            }

        }catch (Exception ex){
            Console.WriteLine($"Error writing cyphertext message file: {ex.Message}");
        }
    }
    private static PadData ReadPadData(string padPath){
        try{
            if(!File.Exists(padPath)){
                throw new ArgumentException("File " + padPath + "doesn't exist");
            }

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(padPath);
            
            //read xml attributes and convert to byte[]
            XmlNode padNode = xmlDoc.SelectSingleNode("pad");
            byte[] nonceBytes = Convert.FromBase64String(padNode.SelectSingleNode("nonceBytes").InnerText);
            byte[] shuffleBytes = Convert.FromBase64String(padNode.SelectSingleNode("shuffleBytes").InnerText);
            byte[] mixBytes = Convert.FromBase64String(padNode.SelectSingleNode("mixBytes").InnerText);

            //return new PadData instance with read pad data
            return new PadData{
                NonceBytes = nonceBytes,
                ShuffleBytes = shuffleBytes,
                MixBytes = mixBytes
            };
        }catch (Exception ex){
            Console.WriteLine($"Error parsing XML file: {ex.Message}");
            return null;
        }
    }
    private static void CreatePadbook(string binPath, string outputDir){
        try{
            int padQuantity = 0;
            int padCount = 0;

            if(!File.Exists(binPath)){
                throw new ArgumentException("File " + binPath + " doesn't exist");
            }

            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.Encoding = Encoding.ASCII;

            //determine how many pads can be made from the specified bin
            FileInfo fileInfo = new FileInfo(binPath);
            padQuantity = (int)(fileInfo.Length / (messageLength+shuffleKeyLength+macNonceLength));

            using (FileStream fs = new FileStream(binPath, FileMode.Open)){
                for(padCount = 0; padCount < padQuantity; padCount++){
                    byte[] buffer = new byte[(messageLength+shuffleKeyLength+macNonceLength)];

                    //read bytes from bin and parse them into each attribute for PadData
                    using (XmlWriter writer = XmlWriter.Create(outputDir + "pad" + padCount + ".xml", settings)){
                        // Write XML declaration
                        writer.WriteStartDocument();

                        // Write root element <pad>
                        writer.WriteStartElement("pad");

                        // Write nonceBytes element
                        writer.WriteStartElement("nonceBytes");
                        fs.Read(buffer, 0, macNonceLength);
                        writer.WriteBase64(buffer, 0, macNonceLength);
                        writer.WriteEndElement();

                        // Write shuffleBytes element
                        writer.WriteStartElement("shuffleBytes");
                        fs.Read(buffer, 0, shuffleKeyLength);
                        writer.WriteBase64(buffer, 0, shuffleKeyLength);
                        writer.WriteEndElement();

                        // Write messageBytes element
                        writer.WriteStartElement("mixBytes");
                        fs.Read(buffer, 0, messageLength);
                        writer.WriteBase64(buffer, 0, messageLength);
                        writer.WriteEndElement();

                        // Close root element </pad>
                        writer.WriteEndElement();

                        // Close the document
                        writer.WriteEndDocument();
                    }
                }
            }
        }catch (Exception ex){
            Console.WriteLine($"Error parsing bin file: {ex.Message}");
        }
    }
}
public static class ShuffleUtility{
    public static byte[] Shuffle(byte[] key, byte[] array){
        //shuffle using the key
        for (int i = array.Length - 1; i > 0; i--){
            int j = GetNextIndexFromKey(key, i);
            byte temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }

        return array;
    }
    public static byte[] Unshuffle(byte[] key, byte[] shuffledArray){
        //unshuffle using key
        for (int i = 1; i < shuffledArray.Length; i++){
            int j = GetNextIndexFromKey(key, i);
            byte temp = shuffledArray[i];
            shuffledArray[i] = shuffledArray[j];
            shuffledArray[j] = temp;
        }

        return shuffledArray;
    }
    private static int GetNextIndexFromKey(byte[] key, int currentIndex){
        // Use bytes from the key array to determine swapping positions
        return key[currentIndex % key.Length] % (currentIndex + 1);
    }
}