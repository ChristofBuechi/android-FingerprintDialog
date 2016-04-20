/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.fingerprintdialog;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.CheckResult;
import android.support.v4.app.ActivityCompat;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import okio.ByteString;

import static android.Manifest.permission.USE_FINGERPRINT;
import static android.content.pm.PackageManager.PERMISSION_GRANTED;

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
public class MainActivity extends Activity {

    private static final String TAG = MainActivity.class.getSimpleName();
    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    /**
     * Alias for our key in the Android Key Store
     */
    private static final String keyAlias = "my_key";

    KeyguardManager keyguardManager;
    FingerprintManager fingerprintManager;
    FingerprintAuthenticationDialogFragment fingerprintAuthenticationDialogFragment;
    KeyPairGenerator keyGenerator;
    KeyStore keyStore;
    Cipher mEnCipher;
    Cipher mDeCipher;
    private EditText encrypt_text;
    private EditText decrypt_text;
    private KeyFactory keyFactory;
    private CancellationSignal cancellationSignal;

    static Cipher createCipher() throws GeneralSecurityException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA
                + "/"
                + KeyProperties.BLOCK_MODE_ECB
                + "/"
                + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
        }
    }

    // Lint is being stupid. The permission is being checked first before accessing fingerprint APIs.
    @SuppressLint("MissingPermission") //
    @CheckResult
    public boolean canStoreSecurely() {
        return checkSelfPermission(USE_FINGERPRINT) == PERMISSION_GRANTED
                && fingerprintManager.isHardwareDetected()
                && fingerprintManager.hasEnrolledFingerprints();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        keyguardManager = getSystemService(KeyguardManager.class);
        fingerprintManager = getSystemService(FingerprintManager.class);
        initializeKeyHandling();
        cancellationSignal = new CancellationSignal();

        if (!canStoreSecurely()) {
            throw new IllegalStateException(
                    "Can't store securely. Check canStoreSecurely() before attempting to read/write.");
        }

        Button encryptButton = (Button) findViewById(R.id.encrypt_button);
        Button decryptButton = (Button) findViewById(R.id.decrypt_button);
        encryptButton.setEnabled(true);
        decryptButton.setEnabled(true);
        decrypt_text = (EditText) findViewById(R.id.decrypt_text);
        encrypt_text = (EditText) findViewById(R.id.encrypt_text);

        fingerprintAuthenticationDialogFragment = new FingerprintAuthenticationDialogFragment();
        fingerprintAuthenticationDialogFragment.setFingerprintManager(fingerprintManager);

        if (!keyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            encryptButton.setEnabled(false);
            decryptButton.setEnabled(false);
            return;
        }

        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("click", "clicked");
                tryToEncrypt();
            }
        });
        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("click", "clicked");
                tryToDecrypt();
            }
        });
    }

    void checkCanStoreSecurely() {
        if (!canStoreSecurely()) {
            throw new IllegalStateException(
                    "Can't store securely. Check canStoreSecurely() before attempting to read/write.");
        }
    }

    void prepareKeyStore() {
        try {
            Key key = keyStore.getKey(keyAlias, null);
            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (key != null && certificate != null) {
                try {
                    createCipher().init(Cipher.DECRYPT_MODE, key);

                    // We have a keys in the store and they're still valid.
                    return;
                } catch (KeyPermanentlyInvalidatedException e) {
                    Log.d(TAG, "Key invalidated.");
                }
            }

            keyGenerator.initialize(new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB) //
                    .setUserAuthenticationRequired(true) //
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) //
                    .build());

            keyGenerator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private void tryToEncrypt() {
        findViewById(R.id.confirmation_message).setVisibility(View.GONE);
        findViewById(R.id.encrypted_message).setVisibility(View.GONE);

        final ByteString text = ByteString.encodeUtf8(encrypt_text.getText().toString());


        checkCanStoreSecurely();
        prepareKeyStore();

        try {
            Cipher cipher = createCipher();
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());

            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                return;
            }
            Log.d("request fingerprint", "request fingerprint");
            fingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher), cancellationSignal,
                    0, new FingerprintManager.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            super.onAuthenticationError(errorCode, errString);
                        }

                        @Override
                        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                            super.onAuthenticationHelp(helpCode, helpString);
                        }

                        @Override
                        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                            Log.d("request fingerprint", "onAuthenticationSucceeded");
                            try {
                                Cipher cipher11 = result.getCryptoObject().getCipher();
                                byte[] decrypted = cipher11.doFinal(text.toByteArray());

                                ByteString textResult = ByteString.of(decrypted);
                                decrypt_text.setText(textResult.utf8());

                            } catch (IllegalBlockSizeException | BadPaddingException e) {
                                Log.i("decryptMethod", "Failed to decrypt.", e);
                            }

                        }

                        @Override
                        public void onAuthenticationFailed() {
                            super.onAuthenticationFailed();
                        }
                    }, null);


//            ByteString text = ByteString.encodeUtf8(encrypt_text.getText().toString());
//            ByteString store = ByteString.of(cipher.doFinal(text.toByteArray()));

//            decrypt_text.setText(store.utf8());
        } catch (GeneralSecurityException e) {
            Log.w(TAG, String.format("Failed to write value"), e);
        }
    }

    private void tryToDecrypt() {
        findViewById(R.id.confirmation_message).setVisibility(View.GONE);
        findViewById(R.id.encrypted_message).setVisibility(View.GONE);

        final ByteString text = ByteString.encodeUtf8(decrypt_text.getText().toString());

        checkCanStoreSecurely();
        prepareKeyStore();

        Cipher cipher = null;
        try {
            cipher = createCipher();
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        } catch (GeneralSecurityException e) {
            Log.w(TAG, String.format("Failed to read value"), e);
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        Log.d("request fingerprint", "request fingerprint");
        fingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher), cancellationSignal,
                0, new FingerprintManager.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        super.onAuthenticationHelp(helpCode, helpString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        Log.d("request fingerprint", "onAuthenticationSucceeded");
                        try {
                            Cipher cipher11 = result.getCryptoObject().getCipher();
                            byte[] decrypted = cipher11.doFinal(text.toByteArray());

                            ByteString textResult = ByteString.of(decrypted);
                            encrypt_text.setText(textResult.utf8());

                        } catch (IllegalBlockSizeException | BadPaddingException e) {
                            Log.i("decryptMethod", "Failed to decrypt.", e);
                        }

                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                    }
                }, null);

        // Set up the crypto object for later. The object will be authenticated by use
        // of the fingerprint.


    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */


    public int checkSelfPermission(String permission) {
        return this.checkPermission(permission, android.os.Process.myPid(),
                android.os.Process.myUid());
    }

    private void initializeKeyHandling() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null); // Ensure the key store can be loaded before continuing.

            keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyFactory = KeyFactory.getInstance("RSA");

            createCipher(); // If this doesn't throw, the cipher we need is available.

        } catch (Exception e) {
            Log.w("Cannot store securely.", e);
        }
    }

    private PublicKey getPublicKey() throws GeneralSecurityException {
        PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

        // In contradiction to the documentation, the public key returned from the key store is only
        // unlocked after the user has authenticated with their fingerprint. This is unnecessary
        // (and broken) for encryption using asynchronous keys, so we work around this by re-creating
        // our own copy of the key. See known issues at
        // http://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
        KeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
        return keyFactory.generatePublic(spec);
    }

    PrivateKey getPrivateKey() throws GeneralSecurityException {
        return (PrivateKey) keyStore.getKey(keyAlias, null);
    }
}
