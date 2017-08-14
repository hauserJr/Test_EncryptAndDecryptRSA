using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class EncryptAndDecryptWithRSA
{
    static RSA_Model _RSA_Model = new RSA_Model();
    static string HelloWorld = string.Format(@"{0},Hello World", DateTime.Now);

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
        //建立RSA
        CreateRSA();
        Encrypt();
        showConsole();
    }
    private static void Encrypt()
    {
        RSACryptoServiceProvider _RSA = new RSACryptoServiceProvider();

        //判斷是否有公鑰的存在
        if (!string.IsNullOrEmpty(_RSA_Model.PublicKey))
        {
            _RSA.FromXmlString(_RSA_Model.PublicKey);
            //將字串轉為系統預設編碼模式(ANSI,美國國家標準協會)
            byte[] SourceData = Encoding.Default.GetBytes(HelloWorld);
            //將轉換完成的編碼使用RSA的Encrypt函式進行加密
            byte[] EncryptStr = _RSA.Encrypt(SourceData, false);

            //傳入byte[]準備解密
            Decrypt(EncryptStr);
        }
        else
        {
            _RSA_Model.ExceptCondition = "1";
        }
    }
    /// <summary>
    /// 資料解密前後比對
    /// </summary>
    /// <param name="EncryptStr"></param>
    private static void Decrypt(byte[] EncryptStr)
    {
        RSACryptoServiceProvider _RSA = new RSACryptoServiceProvider();
        _RSA.FromXmlString(_RSA_Model.PrivateKey);
        //將接收到的資料直接解密
        byte[] DecryptStr = _RSA.Decrypt(EncryptStr, false);
        //再透過預設編碼反轉字串內容
        _RSA_Model.DecryptStr_Before = "解密前：" + Encoding.Default.GetString(EncryptStr);
        _RSA_Model.DecryptStr_After = "解密後：" + Encoding.Default.GetString(DecryptStr);

    }

    /// <summary>
    /// 公/私鑰及解密前後資料顯示
    /// </summary>
    private static void showConsole()
    {
        if (string.IsNullOrEmpty(_RSA_Model.ExceptCondition))
        {
            Console.WriteLine("\n\r"+string.Format("公鑰：{0}",_RSA_Model.PublicKey));
            Console.WriteLine("\n\r" + string.Format("私鑰：{0}", _RSA_Model.PrivateKey));
            Console.WriteLine("\n\r" + string.Format("{0}",_RSA_Model.DecryptStr_Before));
            Console.WriteLine("\n\r" + string.Format("{0}", _RSA_Model.DecryptStr_After));
            
        }
        else
        {
            Console.WriteLine("\n\r 加解密失敗或者公私鑰並不正確。");
        }
        Console.ReadLine();
    }

    /// <summary>
    /// DataModal
    /// </summary>
    public class RSA_Model
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public string DecryptStr_Before { get; set; }
        public string DecryptStr_After { get; set; }
        public string ExceptCondition { get; set; }
    }
}

