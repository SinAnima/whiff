cask "harbour-chart" do
  version "2.0.1"
  sha256 :no_check

  url "https://harbour.test/downloads/HarbourChart-#{version}.dmg"
  name "Harbour Chart"
  desc "Chart viewer for Saltmere Harbour"
  homepage "https://harbour.test/chart"

  app "Harbour Chart.app"

  zap trash: "~/Library/Preferences/test.harbour.chart.plist"
end
