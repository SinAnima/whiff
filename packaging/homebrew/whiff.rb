# Homebrew Formula for whiff
#
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/SinAnima/whiff"
  version "0.9.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      sha256 "56d269a47508ee4a9b34e521e5709c350edfc7a40c44197ae84287bdd9150cf7"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      sha256 "f49c66f3bc8a3e2714c59770a7b644fcffed2df01bb42d5cfcc92567f11b69ce"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      sha256 "32486c7001dd293a8c693604753b5c8d2cb9e49b0da500854dd328789348635f"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      sha256 "a00885436949f4995cf67153cf04fa7b89815b0d5fa74914d4802a72aff96f44"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
