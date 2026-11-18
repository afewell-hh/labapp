"""Check the installed Perl snippet's service selection before a paid build."""

from pathlib import Path
import subprocess


snippet = Path(__file__).resolve().parents[1] / "roles/host/files/needrestart-xrdp.conf"
check = r"""
our %nrconf;
$nrconf{override_rc} = { qr(^dbus) => 0 };
my $loaded = do $ARGV[0];
die $@ if $@;
die $! unless defined $loaded;
for my $service (qw(xrdp.service xrdp-sesman.service)) {
    my @matches = grep { $service =~ /$_/ && $nrconf{override_rc}->{$_} == 0 }
                  keys %{$nrconf{override_rc}};
    die "not deferred: $service" unless @matches;
}
my @other = grep { 'sshd.service' =~ /$_/ } keys %{$nrconf{override_rc}};
die "overbroad override" if @other;
"""
subprocess.run(["perl", "-c", str(snippet)], check=True)
subprocess.run(["perl", "-e", check, str(snippet)], check=True)
