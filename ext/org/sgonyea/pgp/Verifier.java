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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class Verifier {
	private PGPPublicKeyRingCollection _publicKeys;

	public Verifier() {
	}

	/**
	 * Accessor and Attribute Helper Methods
	 **/
	public PGPPublicKeyRingCollection getPublicKeys() {
		return _publicKeys;
	}

	public void setPublicKeys(PGPPublicKeyRingCollection keys) {
		_publicKeys = keys;
	}

	public byte[] verifyStream(InputStream inputStream) throws Exception, VerificationFailedException {
		InputStream pgpInputStream = PGPUtil.getDecoderStream(inputStream);

		PGPObjectFactory pgpFactory = new PGPObjectFactory(pgpInputStream);
		PGPCompressedData pgpCompressedData = (PGPCompressedData) pgpFactory.nextObject();
		pgpFactory = new PGPObjectFactory(pgpCompressedData.getDataStream());
		PGPOnePassSignatureList pgpSignatureList = (PGPOnePassSignatureList) pgpFactory.nextObject();
		PGPOnePassSignature pgpOnePassSignature = pgpSignatureList.get(0);

		PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpFactory.nextObject();

		PGPPublicKey signingKey = _publicKeys.getPublicKey(pgpOnePassSignature.getKeyID());

		if (signingKey == null) {
			throw new VerificationFailedException("Error: Public key with signature's ID could not be found.");
		}

		pgpOnePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), signingKey);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		InputStream inputFileInputStream = pgpLiteralData.getInputStream();
		int ch;
		while ((ch = inputFileInputStream.read()) >= 0) {
			pgpOnePassSignature.update((byte) ch);
			outputStream.write(ch);
		}

		outputStream.close();

		PGPSignatureList pgpSignature = (PGPSignatureList) pgpFactory.nextObject();

		if (!pgpOnePassSignature.verify(pgpSignature.get(0))) {
			throw new VerificationFailedException("Error: Signature could not be verified.");
		}

		byte[] returnBytes = outputStream.toByteArray();
		outputStream.close();

		return returnBytes;
	}

	public boolean verifyDetachedSignature(String fileName, String signature) throws GeneralSecurityException,
			IOException, PGPException, VerificationFailedException {
		InputStream signatureInputStream = new BufferedInputStream(new ByteArrayInputStream(signature.getBytes()));

		boolean isVerified = verifyDetachedSignature(fileName, signatureInputStream);

		signatureInputStream.close();

		return isVerified;
	}

	private boolean verifyDetachedSignature(String fileName, InputStream signature) throws GeneralSecurityException,
			IOException, PGPException, VerificationFailedException {
		signature = PGPUtil.getDecoderStream(signature);

		PGPObjectFactory pgpFactory = new PGPObjectFactory(signature);
		PGPSignatureList pgpSignatureList;

		Object pgpObject = pgpFactory.nextObject();
		if (pgpObject instanceof PGPCompressedData) {
			PGPCompressedData compressedData = (PGPCompressedData) pgpObject;

			pgpFactory = new PGPObjectFactory(compressedData.getDataStream());

			pgpSignatureList = (PGPSignatureList) pgpFactory.nextObject();
		} else {
			pgpSignatureList = (PGPSignatureList) pgpObject;
		}

		PGPSignature pgpSignature = pgpSignatureList.get(0);
		PGPPublicKey pgpPublicKey = _publicKeys.getPublicKey(pgpSignature.getKeyID());

		InputStream inputFileInputStream = new BufferedInputStream(new FileInputStream(fileName));
		if (pgpPublicKey == null) {
			inputFileInputStream.close();
			throw new VerificationFailedException("Error: Public key with signature's ID could not be found.");
		}

		pgpSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pgpPublicKey);

		int ch;
		while ((ch = inputFileInputStream.read()) >= 0) {
			pgpSignature.update((byte) ch);
		}
		inputFileInputStream.close();

		if (!pgpSignature.verify()) {
			throw new VerificationFailedException("Error: Signature could not be verified.");
		}

		return true;
	}
}
