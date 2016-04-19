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

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
public class MainActivity extends Activity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    private static final String SECRET_MESSAGE = "Very secret message";
    /**
     * Alias for our key in the Android Key Store
     */
    private static final String keyAlias = "my_key";

    KeyguardManager mKeyguardManager;
    FingerprintManager mFingerprintManager;
    FingerprintAuthenticationDialogFragment fingerprintAuthenticationDialogFragment;
    KeyStore keyStore;
    KeyPairGenerator keyGenerator;
    Cipher mEnCipher;
    Cipher mDeCipher;
    SharedPreferences mSharedPreferences;
    private boolean encryptedMode;
    private EditText encrypt_text;
    private EditText decrypt_text;
    private Handler handler;
    private KeyFactory keyFactory;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        mKeyguardManager = getSystemService(KeyguardManager.class);
        mFingerprintManager = getSystemService(FingerprintManager.class);
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            keyFactory = KeyFactory.getInstance("RSA");
            mDeCipher = providesRSACipher();
            mEnCipher = providesRSACipher();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);
        fingerprintAuthenticationDialogFragment = new FingerprintAuthenticationDialogFragment();
        fingerprintAuthenticationDialogFragment.setFingerprintManager(mFingerprintManager);
        handler = new Handler(Looper.getMainLooper());

        Button encryptButton = (Button) findViewById(R.id.encrypt_button);
        Button decryptButton = (Button) findViewById(R.id.decrypt_button);
        decrypt_text = (EditText) findViewById(R.id.decrypt_text);
        encrypt_text = (EditText) findViewById(R.id.encrypt_text);

        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            encryptButton.setEnabled(false);
            decryptButton.setEnabled(false);
            return;
        }

        //noinspection ResourceType
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            encryptButton.setEnabled(false);
            decryptButton.setEnabled(false);
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }
//        createKey();
        encryptButton.setEnabled(true);
        decryptButton.setEnabled(true);
        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("click", "clicked");
                encryptedMode = true;
                findViewById(R.id.confirmation_message).setVisibility(View.GONE);
                findViewById(R.id.encrypted_message).setVisibility(View.GONE);

                // Set up the crypto object for later. The object will be authenticated by use
                // of the fingerprint.
                if (initEncryptionCipher()) {

                    // Show the fingerprint dialog. The user has the option to use the fingerprint with
                    // crypto, or you can fall back to using a server-side verified password.
                    fingerprintAuthenticationDialogFragment.setCryptoObject(new FingerprintManager.CryptoObject(mEnCipher));
                    boolean useFingerprintPreference = mSharedPreferences
                            .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                    true);
                    if (useFingerprintPreference) {
                        fingerprintAuthenticationDialogFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                    } else {
                        fingerprintAuthenticationDialogFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                    }
                    fingerprintAuthenticationDialogFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                } else {
                    // This happens if the lock screen has been disabled or or a fingerprint got
                    // enrolled. Thus show the dialog to authenticate with their password first
                    // and ask the user if they want to authenticate with fingerprints in the
                    // future
                    fingerprintAuthenticationDialogFragment.setCryptoObject(new FingerprintManager.CryptoObject(mEnCipher));
                    fingerprintAuthenticationDialogFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                    fingerprintAuthenticationDialogFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            }
        });
        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d("click", "clicked");
                encryptedMode = false;
                findViewById(R.id.confirmation_message).setVisibility(View.GONE);
                findViewById(R.id.encrypted_message).setVisibility(View.GONE);

                // Set up the crypto object for later. The object will be authenticated by use
                // of the fingerprint.
                if (initDecryptionCipher()) {

                    // Show the fingerprint dialog. The user has the option to use the fingerprint with
                    // crypto, or you can fall back to using a server-side verified password.
                    fingerprintAuthenticationDialogFragment.setCryptoObject(new FingerprintManager.CryptoObject(mDeCipher));
                    boolean useFingerprintPreference = mSharedPreferences
                            .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                    true);
                    if (useFingerprintPreference) {
                        fingerprintAuthenticationDialogFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                    } else {
                        fingerprintAuthenticationDialogFragment.setStage(
                                FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                    }
                    fingerprintAuthenticationDialogFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                } else {
                    // This happens if the lock screen has been disabled or or a fingerprint got
                    // enrolled. Thus show the dialog to authenticate with their password first
                    // and ask the user if they want to authenticate with fingerprints in the
                    // future
                    fingerprintAuthenticationDialogFragment.setCryptoObject(new FingerprintManager.CryptoObject(mDeCipher));
                    fingerprintAuthenticationDialogFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
                    fingerprintAuthenticationDialogFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                }
            }
        });
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

    /**
         * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
         * method.
         *
         * @return {@code true} if initialization is successful, {@code false} if the lock screen has
         * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
         * the key was generated.
         */
    private boolean initEncryptionCipher() {
        prepareKeyStore();

        try {

            mEnCipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private boolean initDecryptionCipher() {
        try {
            Key key = keyStore.getKey(keyAlias, null);
            Certificate certificate = keyStore.getCertificate(keyAlias);
            if (key != null && certificate != null) {
                try {
                    mDeCipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
                    return true;
                } catch (GeneralSecurityException e) {
                    return false;
                }
            }
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void onPurchased(boolean withFingerprint) {
        if (withFingerprint) {
            // If the user has authenticated with fingerprint, verify that using cryptography and
            // then show the confirmation message.
            if (encryptedMode) {
                tryEncrypt();
            } else {
                tryDecrypt();
            }
        } else {
            // Authentication happened with backup password. Just show the confirmation message.
            showEncryptedConfirmation(null);
        }
    }

    // Show confirmation, if fingerprint was used show crypto information.
    private void showEncryptedConfirmation(byte[] encrypted) {
        findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (encrypted != null) {
            TextView v = (TextView) findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            v.setText(Base64.encodeToString(encrypted, 0 /* flags */));
            decrypt_text.setText(Base64.encodeToString(encrypted, 0 /* flags */));
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    encrypt_text.setText("");
                }
            }, 1000);

        }
    }

    // Show confirmation, if fingerprint was used show crypto information.
    private void showDecryptedConfirmation(byte[] decrypted) {
        findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (decrypted != null) {
            TextView v = (TextView) findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            v.setText(Base64.encodeToString(decrypted, 0 /* flags */));
            encrypt_text.setText(Base64.encodeToString(decrypted, 0 /* flags */));
            handler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    decrypt_text.setText("");
                }
            }, 1000);
        }
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    private void tryEncrypt() {
        try {
            byte[] encrypted = mEnCipher.doFinal(encrypt_text.getText().toString().getBytes());
            showEncryptedConfirmation(encrypted);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                    + "Retry the purchase", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        }
    }

    private void tryDecrypt() {
        try {
            byte[] decrypted = mDeCipher.doFinal(decrypt_text.getText().toString().getBytes());
            showDecryptedConfirmation(decrypted);
        } catch (BadPaddingException e) {
            Toast.makeText(this, "Failed to decrypt the data with the generated key - BadPaddingException", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to decrypt the data with the generated key - BadPaddingException" + e.getMessage());
        } catch (IllegalBlockSizeException e) {
            Toast.makeText(this, "Failed to encrypt the data with the generated key - IllegalBlockSizeException ", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to encrypt the data with the generated key - IllegalBlockSizeException" + e.getMessage());
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public void createKey() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            keyGenerator.initialize(new KeyGenParameterSpec.Builder(keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB) //
                    .setUserAuthenticationRequired(true) //
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) //
                    .build());

            keyGenerator.generateKeyPair();




//            keyGenerator.init(new KeyGenParameterSpec.Builder(keyAlias,
//                    KeyProperties.PURPOSE_ENCRYPT |
//                            KeyProperties.PURPOSE_DECRYPT)
//                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                    // Require the user to authenticate with a fingerprint to authorize every use
//                    // of the key
//                    .setUserAuthenticationRequired(true)
//                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                    .build());

//            keyGenerator.generateKey();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public Cipher providesCipher() {
        try {
            return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_NONE);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    public Cipher providesRSACipher() throws GeneralSecurityException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA
                + "/"
                + KeyProperties.BLOCK_MODE_ECB
                + "/"
                + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
    }

    public Cipher providesCipherEasy() {
        try {
            return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    public KeyGenerator providesKeyGenerator() {
        try {
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        }
    }

    static Cipher createCipher() throws GeneralSecurityException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA
                + "/"
                + KeyProperties.BLOCK_MODE_ECB
                + "/"
                + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
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

    public int checkSelfPermission(String permission) {
        return this.checkPermission(permission, android.os.Process.myPid(),
                android.os.Process.myUid());
    }
}
