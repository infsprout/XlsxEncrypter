package com.infsprout.xlsxencrypter;

import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.poifs.crypt.*;
import org.apache.poi.poifs.filesystem.FileMagic;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;

public class XlsxEncrypter
{
    private static HashMap<String, HashAlgorithm> _hashAlgorithms;
    private static HashMap<String, CipherAlgorithm> _cipherAlgorithms;

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 2);

        _hashAlgorithms = new HashMap<>();
        _hashAlgorithms.put("SHA-1"     , HashAlgorithm.sha1     );
        _hashAlgorithms.put("SHA256"    , HashAlgorithm.sha256   );
        _hashAlgorithms.put("SHA384"    , HashAlgorithm.sha384   );
        _hashAlgorithms.put("SHA512"    , HashAlgorithm.sha512   );
        _hashAlgorithms.put("MD5"       , HashAlgorithm.md5      );
        _hashAlgorithms.put("MD4"       , HashAlgorithm.md4      );
        _hashAlgorithms.put("MD2"       , HashAlgorithm.md2      );
        _hashAlgorithms.put("RIPEMD-128", HashAlgorithm.ripemd128);
        _hashAlgorithms.put("RIPEMD-160", HashAlgorithm.ripemd160);
        _hashAlgorithms.put("WHIRLPOOL" , HashAlgorithm.whirlpool);

        _cipherAlgorithms = new HashMap<>();
        _cipherAlgorithms.put("AES128"  , CipherAlgorithm.aes128  );
        _cipherAlgorithms.put("AES192"  , CipherAlgorithm.aes192  );
        _cipherAlgorithms.put("AES256"  , CipherAlgorithm.aes256  );
        _cipherAlgorithms.put("3DES"    , CipherAlgorithm.des3    );
        _cipherAlgorithms.put("3DES_112", CipherAlgorithm.des3_112);
    }

    public static class Command
    {
        private Command(){}
        private String _srcPath;
        private String _srcPassword;
        private String _dstPath;
        private String _dstPassword;
        private    int _spinCount   = 50000;
        private String _hashAlgId   = "SHA-1";
        private String _cipherAlgId = "AES128";
    }

    public static class IncorrectPasswordException extends RuntimeException { }

    public static void main(String[] args)
    {
        Command cmd = null;
        try {
            cmd = _createCommand(args);
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
            _printHelp();
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            XSSFWorkbook src = _readSrcWorkbook(cmd);
            _writeDstWorkbook(cmd, src);
        } catch (IncorrectPasswordException e) {
            System.out.println("'--src password' is incorrect.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void _printHelp()
    {
        System.out.println("\n\n"
            + "USAGE: java -jar XlsxEncrypter.jar [Options]\n"
            + "\n"
            + "OPTIONS\n"
            + "--src (Required)\n"
            + "    Source xlsx file path and password.\n"
            + "    ex) folderName/fileName.xlsx:pw1234\n"
            + "--dst (Required)\n"
            + "    Destination xlsx file path ansd password.\n"
            + "--spin-count (Optional, default: 50000)\n"
            + "    Hash iteration count for cipher key from user password.\n"
            + "--hash-alg-id (Optional, default: SHA-1)\n"
            + "    Hash algorithm id for cipher key from user password.\n"
            + "    ( SHA-1 | SHA256 | SHA384 | SHA512 | MD5 | MD4 | MD2 \n"
            + "    | RIPEMD-128 | RIPEMD-160 | WHIRLPOOL )\n"
            + "--cipher-alg-id (Optional, default: AES128)\n"
            + "    Data encryption algorithm id.\n"
            + "    ( AES128 | AES192 | AES256 | 3DES | 3DES_112 )\n"
        );
    }

    private static File _getFile(String path)
    {
        try {
            return Paths.get(path).toFile();
        } catch (Exception e) {
            return null;
        }
    }

    private static Command _createCommand(String[] args)
    {
        Command cmd = new Command();
        if (args.length % 2 != 0) {
            throw new IllegalArgumentException(
                "Argument count must be even."
            );
        }
        for (int n = 0; n < args.length; n += 2) {
            String opt = args[n];
            if (opt.equals("--src")) {
                String[] values = args[n + 1].split(":");
                if (values.length > 2) {
                    throw new IllegalArgumentException(
                        "'--src' value format is invalid."
                    );
                }
                File file = _getFile(values[0]);
                if (file == null || !file.exists()) {
                    throw new IllegalArgumentException(
                        "'--src " + file.getPath() + "' not found."
                    );
                }
                cmd._srcPath = file.getPath();
                if (values.length > 1) {
                    cmd._srcPassword = values[1];
                }
            } else if (opt.equals("--dst")) {
                String[] values = args[n + 1].split(":");
                boolean isValidPath = true;
                File file = null;
                if (values.length > 2) {
                    isValidPath = false;
                } else {
                    file = _getFile(values[0]);
                    isValidPath = (file != null);
                }
                if (!isValidPath) {
                    throw new IllegalArgumentException(
                        "'--dst' value format is invalid."
                    );
                }
                cmd._dstPath = file.getPath();
                if (values.length > 1) {
                    cmd._dstPassword = values[1];
                }
            } else if (opt.equals("--spin-count")) {
                try {
                    cmd._spinCount = Integer.parseInt(args[n + 1]);
                    cmd._spinCount = Math.max(cmd._spinCount, 50000);
                } catch (Exception e) {
                    throw new IllegalArgumentException(
                        "'--spin-count' value must be integer.'"
                    );
                }
            } else if (opt.equals("--cipher-alg-id")) {
                String key = args[n + 1];
                if (!_cipherAlgorithms.containsKey(key)) {
                    throw new IllegalArgumentException(
                        "'--cipher-alg-id " + key + "' is unsupported."
                    );
                }
                cmd._cipherAlgId = key;
            } else if (opt.equals("--hash-alg-id")) {
                String key = args[n + 1];
                if (!_hashAlgorithms.containsKey(key)) {
                    throw new IllegalArgumentException(
                        "'--hash-alg-id " + key + "' is unsupported."
                    );
                }
                cmd._hashAlgId = key;
            } else {
                throw new IllegalArgumentException(
                    "Option '" + opt +"' is unsupported."
                );
            }
        }
        if (cmd._srcPath == null || cmd._dstPath == null) {
            throw new IllegalArgumentException(
                "Options '--src' and '--dst' are mandatory."
            );
        }
        return cmd;
    }

    private static XSSFWorkbook _readSrcWorkbook(Command cmd)
        throws IOException, GeneralSecurityException, InvalidFormatException
    {
        InputStream is = new FileInputStream(cmd._srcPath);
        is = FileMagic.prepareToCheckMagic(is);
        if (FileMagic.OLE2.equals(FileMagic.valueOf(is))) {
            POIFSFileSystem fs = new POIFSFileSystem(is);
            EncryptionInfo ei = new EncryptionInfo(fs);
            Decryptor dec = ei.getDecryptor();
            String pw = cmd._srcPassword;
            if (pw == null) {
                pw = "";
            }
            if (!dec.verifyPassword(pw)) {
                throw new IncorrectPasswordException();
            }
            is = dec.getDataStream(fs);
        }
        return new XSSFWorkbook(OPCPackage.open(is));
    }

    private static void _writeDstWorkbook(Command cmd, XSSFWorkbook src)
        throws IOException, GeneralSecurityException
    {
        String pw = cmd._dstPassword;
        if (pw == null || pw.isEmpty()) {
            new File(cmd._dstPath).createNewFile();
            OutputStream os = new FileOutputStream(cmd._dstPath);
            src.write(os);
            os.close();
        } else {
            POIFSFileSystem fs = new POIFSFileSystem();
            EncryptionInfo ei = new EncryptionInfo(
                EncryptionMode.agile,
                _cipherAlgorithms.get(cmd._cipherAlgId),
                _hashAlgorithms.get(cmd._hashAlgId),
                -1, -1, null
            );
            _setSpinCount(ei, cmd._spinCount);
            Encryptor enc = ei.getEncryptor();
            enc.confirmPassword(pw);
            OutputStream os = enc.getDataStream(fs);
            src.write(os);
            os.close();
            fs.writeFilesystem(new FileOutputStream(new File(cmd._dstPath)));
            fs.close();
        }
    }

    private static void _setSpinCount(EncryptionInfo ei, int spinCount)
    {
        try {
            Class<?> cls = EncryptionVerifier.class;
            for (Method method : cls.getDeclaredMethods()) {
                if (method.getName().equals("setSpinCount")) {
                    method.setAccessible(true);
                    method.invoke(ei.getVerifier(), spinCount);
                    return;
                }
            }
        } catch(Exception e) {
            System.out.println("_setSpinCount(): " + e);
        }
    }

}
