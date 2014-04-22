require 'spec_helper'

describe PGP::Verifier do
  let(:public_key_path) { Fixtures_Path.join('public_key_with_passphrase.asc').to_s }

  let(:verifier) { PGP::Verifier.new }
  let(:unsigned_file) { Fixtures_Path.join('signed_file.txt') }
  let(:signed_file) { Fixtures_Path.join('signed_file.txt.asc') }
  let(:file_signature) { Fixtures_Path.join('signed_file_signature.asc') }

  describe '#verify' do
    before do
      verifier.add_keys_from_file(public_key_path)
    end

    context 'When the public key is from a file' do
      it "verifies" do
        verifier.verify(File.read(signed_file)).should == File.read(unsigned_file)
      end
    end

    context 'When the public key cannot verify a signature' do
      let(:public_key_path) { Fixtures_Path.join('wrong_public_key_for_signature.asc').to_s }

      it "should raise an exception" do
        expect {
          verifier.verify(File.read(signed_file))
        }.to raise_exception(org.sgonyea.pgp.VerificationFailedException, /key.*could not be found/)
      end
    end
  end

  describe '#verify_detached' do
    before do
      verifier.add_keys_from_file(public_key_path)
    end

    context 'When the public key is from a file' do
      it "verifies" do
        verifier.verify_detached(unsigned_file, File.read(file_signature)).should == true
      end
    end

    context 'When the public key cannot verify a signature' do
      let(:public_key_path) { Fixtures_Path.join('wrong_public_key_for_signature.asc').to_s }

      it "should raise an exception" do
        expect {
          verifier.verify_detached(unsigned_file, File.read(file_signature))
        }.to raise_exception(org.sgonyea.pgp.VerificationFailedException, /ID.*could not be found/)
      end
    end
  end
end
