# Homebrew formula template for Sextant.
#
# This is a starting point for a Homebrew tap (for example a
# `NotACop38/homebrew-tap` repository). On each release, update `version`, the
# download URLs, and the four `sha256` values to match the published archives
# and their `.sha256` checksum files from the GitHub Release. The values below
# are placeholders.
#
# Once the tap exists, users install with:
#   brew install NotACop38/tap/sextant
#
# The formula installs prebuilt release binaries (the same checksummed archives
# the install script uses); it does not compile from source.
class Sextant < Formula
  desc "Infer and verify the structure of unknown binary formats and protocols"
  homepage "https://github.com/NotACop38/Sextant"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/NotACop38/Sextant/releases/download/v#{version}/sextant-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/NotACop38/Sextant/releases/download/v#{version}/sextant-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/NotACop38/Sextant/releases/download/v#{version}/sextant-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "sextant"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sextant --version")
  end
end
