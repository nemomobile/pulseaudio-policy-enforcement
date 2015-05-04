%define pulseversion %{expand:%(rpm -q --qf '[%%{version}]' pulseaudio)}
%define pulsemajorminor %{expand:%(echo '%{pulseversion}' | cut -d+ -f1)}
%define moduleversion %{pulsemajorminor}.%{expand:%(echo '%{version}' | cut -d. -f3)}

Name:       pulseaudio-policy-enforcement

Summary:    Pulseaudio module for enforcing policy decisions in the audio domain
Version:    %{pulsemajorminor}.19
Release:    0
Group:      System/Daemons
License:    LGPLv2.1
URL:        https://github.com/nemomobile/pulseaudio-policy-enforcement
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(atomic_ops)
BuildRequires:  pkgconfig(pulsecore) >= %{pulsemajorminor}
BuildRequires:  pkgconfig(libpulse) >= %{pulsemajorminor}
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libmeego-common) >= %{pulsemajorminor}.17
BuildRequires:  libtool-ltdl-devel

%description
This package contains a pulseaudio module that enforces (mostly audio) routing,
corking and muting policy decisions.


%prep
%setup -q -n %{name}-%{version}


%build
echo "%{moduleversion}" > .tarball-version
unset LD_AS_NEEDED

%autogen --disable-static
%configure --disable-static \
    --with-module-dir=%{_libdir}/pulse-%{pulsemajorminor}/modules

make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
%make_install


%files
%defattr(-,root,root,-)
%{_libdir}/pulse-*/modules/module-*.so
