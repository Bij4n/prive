class Prive < Formula
  desc "Cross-platform CLI password manager and PGP encryption toolkit"
  homepage "https://github.com/Bij4n/prive-app"
  version "0.4.0"

  on_macos do
    on_arm do
      url "https://github.com/Bij4n/prive-app/releases/download/v#{version}/prive-macos-aarch64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/Bij4n/prive-app/releases/download/v#{version}/prive-macos-x86_64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/Bij4n/prive-app/releases/download/v#{version}/prive-linux-x86_64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  def install
    bin.install Dir["prive*"].first => "prive"
  end

  def post_install
    # Generate shell completions
    (bash_completion/"prive").write Utils.safe_popen_read(bin/"prive", "completions", "--shell", "bash")
    (zsh_completion/"_prive").write Utils.safe_popen_read(bin/"prive", "completions", "--shell", "zsh")
    (fish_completion/"prive.fish").write Utils.safe_popen_read(bin/"prive", "completions", "--shell", "fish")
  end

  test do
    assert_match "prive", shell_output("#{bin}/prive --version")
    assert_match "generate", shell_output("#{bin}/prive --help")
  end
end
