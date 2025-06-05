package com.example.remoteid;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class Main extends AppCompatActivity {

    private EditText startTimeInput, endTimeInput, flightDuration, uasIdInput, operatorIdInput;
    private Button generateKeysButton;
    private TextView outputKeys;
    private File keysFile, rootKeyFile, missionInfoFile;

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "TeslaRemoteIdMasterKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        startTimeInput = findViewById(R.id.startTimeInput);
        endTimeInput = findViewById(R.id.endTimeInput);
        flightDuration = findViewById(R.id.flightDuration);
        uasIdInput = findViewById(R.id.uasIdInput);
        operatorIdInput = findViewById(R.id.operatorIdInput);
        generateKeysButton = findViewById(R.id.generateKeysButton);

        // Save files in the project's local directory
        File projectDir = new File(getExternalFilesDir(null), "TeslaKeys");
        if (!projectDir.exists()) {
            projectDir.mkdirs();
        }
        keysFile = new File(projectDir, "keys.txt");
        rootKeyFile = new File(projectDir, "root_key.txt");
        missionInfoFile = new File(projectDir, "mission_info.txt");

        startTimeInput.addTextChangedListener(durationWatcher);
        endTimeInput.addTextChangedListener(durationWatcher);

        generateKeysButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generateTeslaKeys();
            }
        });
    }

    private final TextWatcher durationWatcher = new TextWatcher() {
        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            calculateDuration();
        }

        @Override
        public void afterTextChanged(Editable s) {}
    };

    private void calculateDuration() {
        String startTimeStr = startTimeInput.getText().toString();
        String endTimeStr = endTimeInput.getText().toString();

        if (!startTimeStr.isEmpty() && !endTimeStr.isEmpty()) {
            try {
                long startTime = Long.parseLong(startTimeStr);
                long endTime = Long.parseLong(endTimeStr);
                long duration = endTime - startTime;

                if (duration >= 0) {
                    flightDuration.setText(String.valueOf(duration));
                } else {
                    flightDuration.setText("");
                }
            } catch (NumberFormatException e) {
                flightDuration.setText("");
            }
        }
    }

    private SecretKey generateOrGetMasterKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            // Generate new seed key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE);

            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(256)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(false)
                    .build();

            keyGenerator.init(keyGenParameterSpec);
            return keyGenerator.generateKey();
        } else {
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        }
    }

    private byte[] generateKeyWithTEE(SecretKey masterKey, byte[] input) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(masterKey);
        return mac.doFinal(input);
    }

    private byte[] extractMasterKeyBytes(SecretKey masterKey) throws Exception {
        // Use the master key
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(masterKey);
        return mac.doFinal("TESLA_SEED".getBytes());
    }

    private void generateTeslaKeys() {
        String startTimeStr = startTimeInput.getText().toString();
        String endTimeStr = endTimeInput.getText().toString();
        String uasId = uasIdInput.getText().toString();
        String operatorId = operatorIdInput.getText().toString();

        if (startTimeStr.isEmpty() || endTimeStr.isEmpty() || uasId.isEmpty() || operatorId.isEmpty()) {
            Toast.makeText(this, "All fields must be filled", Toast.LENGTH_SHORT).show();
            return;
        }

        long startTime = Long.parseLong(startTimeStr);
        long endTime = Long.parseLong(endTimeStr);
        long duration = endTime - startTime;
        if (duration < 0) {
            Toast.makeText(this, "End time must be greater than start time", Toast.LENGTH_SHORT).show();
            return;
        }

        // duration + 1 key for root key generation
        long numKeys = duration + 1;

        try {
            // Get master key in TEE
            SecretKey masterKey = generateOrGetMasterKey();

            byte[][] keyChain = new byte[(int) numKeys][32];

            // Use the TEE master key as the seed key
            keyChain[0] = extractMasterKeyBytes(masterKey);

            // Generate subsequent keys using TEE-based HMAC
            for (int i = 1; i < numKeys; i++) {
                keyChain[i] = generateKeyWithTEE(masterKey, keyChain[i - 1]);
            }

            // Save root key (last key in chain)
            try (FileOutputStream fos = new FileOutputStream(rootKeyFile)) {
                fos.write(bytesToHex(keyChain[(int) numKeys - 1]).getBytes());
            }

            // Save mission info
            try (FileOutputStream fos = new FileOutputStream(missionInfoFile)) {
                String missionData = uasId + "," + operatorId + "," + startTime + "," + endTime + "\n";
                fos.write(missionData.getBytes());
            }

            // Save all keys except the root key
            try (FileOutputStream fos = new FileOutputStream(keysFile)) {
                for (int i = 0; i < numKeys - 1; i++) {
                    fos.write((bytesToHex(keyChain[i]) + "\n").getBytes());
                }
            }

            Toast.makeText(this, "Keys generated using TEE and saved!", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Error generating keys with TEE: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}