%global srcname saltmere-tides

Name:           %{srcname}
Version:        1.4.0
Release:        2%{?dist}
Summary:        Tide predictions for Saltmere Harbour

License:        CC0-1.0
URL:            https://harbour.test/tides
Source0:        https://harbour.test/releases/%{srcname}-%{version}.tar.gz
Source1:        tides.conf
Patch0:         fix-units.patch

BuildRequires:  meson, gcc
BuildRequires:  glib2-devel >= 2.76
Requires:       glib2

%description
Harmonic tide predictions for the gauges of the fictitious
Saltmere Harbour.

%prep
%autosetup -p1

%build
%meson
%meson_build

%install
%meson_install

%files
%license COPYING
%{_bindir}/tides

%changelog
* Sat Mar 14 2026 Harbour Office <office@harbour.example.org> - 1.4.0-2
- Fix gauge units
* Mon Jan 05 2026 Harbour Office <office@harbour.example.org> - 1.4.0-1
- New release
