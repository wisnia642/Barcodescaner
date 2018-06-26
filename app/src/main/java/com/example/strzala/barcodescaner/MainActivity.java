package com.example.strzala.barcodescaner;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}

public class AZTecDecoder
{
    /**
     * Domyslna koncowka WebApi (HTTP lub HTTPS)
     *
     * w przypadku bledu polaczen do wersji HTTPS:
     *
     * sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
     *
     * nalezy dodac certyfikat CA firmy StartCOM do zaufanych kluczy JRE
     *
     * 1. Dla Windows - https://github.com/haron/startssl-java
     * 2. Dla Linux - https://www.ailis.de/~k/uploads/scripts/import-startssl
     *
     * Oracle od lat nie chce dodac CA firmy StartCOM do swoich zaufanych kluczy (z niewiadomych przyczyn)
     */
    private static final String API_URL = "https://www.pelock.com/api/aztec-decoder/v1";

    /**
     * Czy mamy ufac certyfikatowi HTTPS Dekodera AZTec (ustaw na false, jesli dodales klucze StartCOM do CA)
     */
    private static final Boolean TRUST_HTTPS_HOST = true;

    /**
     * Klucz WebApi do uslugi AZTecDecoder
     */
    private String _ApiKey = "";

    /**
     * Inicjalizacja klasy AZTecDecoder
     *
     * @param ApiKey Klucz do uslugi WebApi
     */
    public AZTecDecoder(String ApiKey)
    {
        this._ApiKey = ApiKey;
    }

    /**
     * Dekodowanie zaszyfrowanej wartosci tekstowej do wyjsciowej tablicy w formacie JSON.
     *
     * @param Text Odczytana wartosc z kodem AZTEC2D w formie ASCII
     * @return     Tablica z odczytanymi wartosciami, ciag JSON lub false jesli blad
     */
    public JSONObject DecodeText(String Text)
    {
        // parametry
        Map<String, String> Params = new HashMap<String, String>();

        Params.put("command", "decode-text");
        Params.put("text", Text);

        return this.PostRequest(Params);
    }

    /**
     * Dekodowanie zaszyfrowanej wartosci tekstowej ze wskaznego pliku do wyjsciowej tablicy z formatu JSON.
     *
     * @param TextFilePath Sciezka do pliku z odczytana wartoscia kodu AZTEC2D
     * @return             Tablica z odczytanymi wartosciami, ciag JSON lub false jesli blad
     */
    public JSONObject DecodeTextFromFile(String TextFilePath)
    {
        try
        {
            BufferedReader br = new BufferedReader(new FileReader(TextFilePath));

            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null)
            {
                sb.append(line);
                sb.append(System.getProperty("line.separator"));
                line = br.readLine();
            }

            String Text = sb.toString();

            return this.DecodeText(Text);
        }
        catch (Exception ex)
        {
            return null;
        }
    }

    /**
     * Dekodowanie zaszyfrowanej wartosci zakodowanej w obrazku PNG lub JPG/JPEG do wyjsciowej tablicy w formacie JSON.
     *
     * @param ImageFilePath Sciezka do obrazka z kodem AZTEC2D
     * @return              Tablica z odczytanymi wartosciami, ciag JSON lub false jesli blad
     */
    public JSONObject DecodeImageFromFile(String ImageFilePath)
    {
        // parametry
        Map<String, String> Params = new HashMap<String, String>();

        Params.put("command", "decode-image");
        Params.put("image", ImageFilePath);

        return this.PostRequest(Params);
    }

    /**
     * Wysyla zapytanie POST do serwera WebApi
     *
     * @param ParamsArray Tablica z parametrami dla zapytania POST
     * @return            Tablica z odczytanymi wartosciami, ciag JSON lub false jesli blad
     */
    private JSONObject PostRequest(Map<String, String> ParamsArray)
    {
        // czy jest ustawiony klucz Web API?
        if (this._ApiKey == null || this._ApiKey.length() == 0)
        {
            return null;
        }

        // do parametrow dodaj klucz Web API
        ParamsArray.put("key", this._ApiKey);

        MultipartEntityBuilder builder = MultipartEntityBuilder.create();

        try
        {
            CloseableHttpClient client;

            // czy akceptowac certyfikat SSL bez jego weryfikacji?
            if (TRUST_HTTPS_HOST)
            {
                // zaakceptuj certyfikat z firmy StartCOM
                SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()
                {
                    public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException
                    {
                        return true;
                    }
                }).build();

                client = HttpClients.custom().setSSLContext(sslContext).setSSLHostnameVerifier(new NoopHostnameVerifier()).build();

            }
            else
            {
                client = HttpClients.createDefault();
            }

            HttpPost httpPost = new HttpPost(API_URL);

            // ustaw poprawnie element z plikiem
            if (ParamsArray.containsKey("image"))
            {
                File imageFile = new File(ParamsArray.get("image"));

                builder.addBinaryBody("image", imageFile, ContentType.APPLICATION_OCTET_STREAM, imageFile.getName());

                ParamsArray.remove("image");
            }

            for (Map.Entry<String, String> paramArray : ParamsArray.entrySet())
            {
                builder.addTextBody(paramArray.getKey(), paramArray.getValue());
            }

            httpPost.setEntity(builder.build());

            CloseableHttpResponse response = client.execute(httpPost);

            // status HTTP
            int code = response.getStatusLine().getStatusCode();

            if (code != 200)
            {
                client.close();
                return null;
            }

            // odczytaj odpowiedz z serwera
            HttpEntity responseEntity = response.getEntity();

            if (responseEntity == null)
            {
                client.close();
                return null;
            }

            String json = EntityUtils.toString(responseEntity);

            // zwroc wartosc jako tablice JSONArray
            JSONObject array = new JSONObject(json);

            client.close();

            return array;
        }
        catch (Exception ex)
        {
            //System.out.print(ex.toString());
            return null;
        }

    }
}
