# Homebrew Formula for whiff
#
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/SinAnima/whiff"
  version "0.8.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      sha256 "67da3fcb2e048f077f1978ababbd8f3900f9dd7702cb175df5647dc5d379999a"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      sha256 "87495c97d662a9f0f930db64e1f1bc4d31d002fae7f04cda4d670e3b87a9067c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      sha256 "92fb46f71676d9cdc36b9e9e7d5ac726123c004773b265e1412aab528a986528"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      sha256 "9829f683c159ac5cbb8239c10b2b60e2af6cdda156a072c8e0bff47b120bac8f"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
