# Homebrew Formula for whiff
#
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/SinAnima/whiff"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      sha256 "006fdaa9cc17bc6dc96f8e2c238cd42853512ab8b3f13d3c3c309d34ad0790db"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      sha256 "f4367044df66b7dc566676027588ef6a2d9501af06a0365d1d54fdfb8d99183e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      sha256 "a822b054b9d73dd09ad81d0675648e4673df0b90b6ca622eb9a03a0efce874fb"
    end
    on_intel do
      url "https://github.com/SinAnima/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      sha256 "91d9f04db206cd2c1b6ac2ba7078265bda538ea8e04c3e47c75558b888c33382"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
