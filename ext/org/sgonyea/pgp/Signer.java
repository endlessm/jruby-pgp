/**
 * Much of this code was stolen from this Stack Overflow post:
 *  http://stackoverflow.com/questions/3939447/how-to-encrypt-a-string-stream-with-bouncycastle-pgp-without-starting-with-a-fil
 *
 * In addition to the java versions of this lump of code, that have been floating around on the internet:
 *  https://gist.github.com/1954648
 *
 * Thanks to everyone who has posted on the topic of Bouncy Castle's PGP Library.
 */

package org.sgonyea.pgp;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Signer {
	private String passphrase;
	private PGPSecretKeyRingCollection _privateKeys;

	public Signer() {
	}

	public Signer(PGPSecretKeyRingCollection privateKeys) {
		setPrivateKeys(privateKeys);
	}

	/**
	 * Accessor and Attribute Helper Methods
	 **/
	public PGPSecretKeyRingCollection getPrivateKeys() {
		return _privateKeys;
	}

	public void setPrivateKeys(PGPSecretKeyRingCollection privateKeys) {
		_privateKeys = privateKeys;
	}

	public void setPassphrase(String passphrase) {
		this.passphrase = passphrase;
	}

	private PGPSecretKey findSecretKey() throws PGPException, NoSuchProviderException {
		@SuppressWarnings("rawtypes")
		Iterator keyRingIter = _privateKeys.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			@SuppressWarnings("rawtypes")
			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

	public byte[] signData(byte[] inputData) throws Exception {
		ByteArrayOutputStream signatureByteArrayOutputStream = new ByteArrayOutputStream();
		ArmoredOutputStream armoredSignatureOutputStream = new ArmoredOutputStream(signatureByteArrayOutputStream);

		PGPSecretKey pgpSigningKey = findSecretKey();
		PGPPrivateKey pgpPrivateKey = pgpSigningKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
				.setProvider("BC").build(passphrase.toCharArray()));
		PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
				pgpSigningKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

		signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

		@SuppressWarnings("rawtypes")
		Iterator iter = pgpSigningKey.getPublicKey().getUserIDs();
		if (iter.hasNext()) {
			PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

			subpacketGenerator.setSignerUserID(false, (String) iter.next());
			signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
		}

		PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);

		BCPGOutputStream pgpOutputStream = new BCPGOutputStream(compressor.open(armoredSignatureOutputStream));

		signatureGenerator.generateOnePassVersion(false).encode(pgpOutputStream);

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream literalDataGeneratorOutputStream = literalDataGenerator.open(pgpOutputStream,
				PGPLiteralData.BINARY, PGPLiteralDataGenerator.CONSOLE, inputData.length, PGPLiteralDataGenerator.NOW);

		literalDataGeneratorOutputStream.write(inputData);
		signatureGenerator.update(inputData);

		literalDataGenerator.close();

		signatureGenerator.generate().encode(pgpOutputStream);

		compressor.close();

		armoredSignatureOutputStream.close();

		return signatureByteArrayOutputStream.toByteArray();
	}

	public String signDataDetached(String inputFileName) throws Exception {
		ByteArrayOutputStream signatureByteArrayOutputStream = new ByteArrayOutputStream();
		ArmoredOutputStream armoredSignatureOutputStream = new ArmoredOutputStream(signatureByteArrayOutputStream);

		PGPSecretKey pgpSigningKey = findSecretKey();
		PGPPrivateKey pgpPrivateKey = pgpSigningKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
				.setProvider("BC").build(passphrase.toCharArray()));
		PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(
				pgpSigningKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

		signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

		BCPGOutputStream pgpOutputStream = new BCPGOutputStream(armoredSignatureOutputStream);

		InputStream inputFileInputStream = new BufferedInputStream(new FileInputStream(inputFileName));

		int ch;
		while ((ch = inputFileInputStream.read()) >= 0) {
			signatureGenerator.update((byte) ch);
		}

		signatureGenerator.generate().encode(pgpOutputStream);

		inputFileInputStream.close();

		armoredSignatureOutputStream.close();

		return new String(signatureByteArrayOutputStream.toByteArray());
	}
}
