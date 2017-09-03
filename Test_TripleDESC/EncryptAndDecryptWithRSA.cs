using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class EncryptAndDecryptWithRSA
{
    static RSA_Model _RSA_Model = new RSA_Model();

    /// <summary>
    /// Zheng,Ming-Hong
    /// 將私鑰公開存放是不安全
    /// 20170814待修正將RSA放入CspParameters
    /// </summary>
    public static void CreateRSA()
    {
        RSACryptoServiceProvider _RSA = new RSACryptoServiceProvider();
        _RSA_Model.PrivateKey = _RSA.ToXmlString(true);
        _RSA_Model.PublicKey = _RSA.ToXmlString(false);
    }

    /// <summary>
    /// 各函式執行主區
    /// </summary>
    /// <param name="args"></param>
    static void Main(string[] args)
    {
        CreateRSA();
        Encrypt(string.Format(@"{1},{0},Hello World", DateTime.Now,"First Encrypt And Decrypt"));
   



        Console.WriteLine(" #########################################################################\n\r");
        Console.WriteLine("\n\r 使用函式EncryptingPrivateKey()加密Private Key中 Private Key Encrypting ...\n\r");
        EncryptingPrivateKey(_RSA_Model.PrivateKey);
        Console.WriteLine(" 使用函式DecryptingPrivateKey()解密Private Key中 Private Key Decrypting ...\n\r");
        Console.WriteLine(" 解密完成再次使用公鑰對訊息加密並使用二度解密後的私鑰解密驗證 ...\n\r");



        int TimeoutSetting = 1000;
        System.Threading.Thread.Sleep(TimeoutSetting);
        Encrypt(string.Format(@"{1},{0},Hello World", DateTime.Now, "Second Encrypt And Decrypt"));
        Console.WriteLine(" #########################################################################\n\r");
        Console.ReadLine();
    }
    /// <summary>
    /// 資料加密
    /// </summary>
    private static void Encrypt(string EncrtpyStr)
    {
       
        //建立RSA
        RSACryptoServiceProvider _RSA = new RSACryptoServiceProvider();

        //判斷是否有公鑰的存在
        if (!string.IsNullOrEmpty(_RSA_Model.PublicKey))
        {
            _RSA.FromXmlString(_RSA_Model.PublicKey);
            //將字串轉為系統預設編碼模式(ANSI,美國國家標準協會)
            byte[] SourceData = Encoding.Default.GetBytes(EncrtpyStr);
            //將轉換完成的編碼使用RSA的Encrypt函式進行加密
            byte[] EncryptStr = _RSA.Encrypt(SourceData, false);

            //傳入byte[]準備解密
            Decrypt(EncryptStr);
        }
        else
        {
            _RSA_Model.ExceptCondition = "公鑰不存在";         
        }
    }
    /// <summary>
    /// 資料解密前後比對
    /// </summary>
    /// <param name="EncryptStr"></param>
    private static void Decrypt(byte[] EncryptStr)
    {
        RSACryptoServiceProvider _RSA = new RSACryptoServiceProvider();
        try
        {
            _RSA.FromXmlString(_RSA_Model.PrivateKey);
            //將接收到的資料直接解密
            byte[] DecryptStr = _RSA.Decrypt(EncryptStr, false);
            //再透過預設編碼反轉字串內容
            _RSA_Model.DecryptStr_Before = Convert.ToString("解密前：") + Encoding.Default.GetString(EncryptStr);
            _RSA_Model.DecryptStr_After = Convert.ToString("解密後：") + Encoding.Default.GetString(DecryptStr);
        }
        catch (Exception ex)
        {
            _RSA_Model.ExceptCondition = string.Format(@"{0}", ex);
        }
        showConsole();
    }

    /// <summary>
    /// 公/私鑰及解密前後資料顯示
    /// </summary>
    private static void showConsole()
    {
        if (string.IsNullOrEmpty(_RSA_Model.ExceptCondition))
        {
            Console.WriteLine(" 公私鑰及資料加密前後資訊區 ...");
            //Console.WriteLine("\n\r" + string.Format("公鑰：{0}",_RSA_Model.PublicKey));
            Console.WriteLine("\n\r" + string.Format(" 公鑰字串長度：{0}", _RSA_Model.PublicKey.Length));

            //Console.WriteLine("\n\r" + string.Format("私鑰：{0}", _RSA_Model.PrivateKey));
            Console.WriteLine("\n\r" + string.Format(" 私鑰字串長度：{0}", _RSA_Model.PrivateKey.Length));

            Console.WriteLine("\n\r " + string.Format("{0}", _RSA_Model.DecryptStr_Before));
            Console.WriteLine("\n\r " + string.Format("{0}", _RSA_Model.DecryptStr_After));       
        }
        else
        {
            Console.WriteLine("\n\r" + string.Format(@"錯誤訊息：{0}",_RSA_Model.ExceptCondition));
        }
    }

    private static List<char> EncryptingPrivateKey(string _PrivateKeyToEncrypt)
    {
        List<char> _PrivateKeyList = new List<char>();
        _PrivateKeyList = _PrivateKeyToEncrypt.ToList();
        byte x = (byte)_PrivateKeyList[0];
        byte y = (byte)_PrivateKeyList[1];
        _PrivateKeyList[0] = (char)y;
        _PrivateKeyList[1] = (char)x;
        return _PrivateKeyList;
    }
    private static void DecryptingPrivateKey(List<char> _PrivateKeyToEncrypt)
    {
        List<char> _PrivateKeyList = new List<char>();
        _PrivateKeyList = _PrivateKeyToEncrypt.ToList();
        byte x = (byte)_PrivateKeyList[0];
        byte y = (byte)_PrivateKeyList[1];
        _PrivateKeyList[0] = (char)y;
        _PrivateKeyList[1] = (char)x;
        _RSA_Model.PrivateKey = _PrivateKeyList.ToString();
    }
    /// <summary>
    /// DataModal
    /// </summary>
    public class RSA_Model
    {
        public string PrivateKey { get ; set ; }
        public string PublicKey { get; set; }
        public string DecryptStr_Before { get; set; }
        public string DecryptStr_After { get; set; }
        public string ExceptCondition { get; set; }
    }
}

