#!/usr/bin/env bash
# No hardware, networking changes, or root privileges required.
set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source ./airgeddon.sh
debug_print() { :; }
work=$(mktemp -d)
trap 'rm -rf -- "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

compare_floats_greater_than 12.10 12.9 || fail '12.10 > 12.9'
! compare_floats_greater_than 12.9 12.10 || fail '12.9 < 12.10'
compare_floats_greater_or_equal 12.10 12.10 || fail equality
compare_floats_greater_than 13.0 12.99 || fail 'major transition'
! compare_versions invalid 12.10 gt || fail 'invalid version'

scriptfolder="${work}/"
osversionfile_dir="${work}/"
cp .airgeddonrc "${work}/.airgeddonrc"
env_vars_initialization
for item in "${ARRAY_ENV_VARS_ELEMENTS[@]}"; do unset "${item}"; done
cat >> "${rc_path}" <<'CONFIG'
AIRGEDDON_WINDOWS_HANDLING=TMUX
AIRGEDDON_AUTO_UPDATE=$(touch SHOULD_NOT_EXIST)
AIRGEDDON_DEBUG_MODE=TRUE
CONFIG
# Duplicates rejected and safely defaulted; no evaluation of shell expressions.
env_vars_values_validation
[[ "${AIRGEDDON_WINDOWS_HANDLING}" == xterm ]] || fail duplicates
[[ ! -e SHOULD_NOT_EXIST ]] || fail 'configuration executed'
printf 'AIRGEDDON_WINDOWS_HANDLING=TMUX\nAIRGEDDON_DEBUG_MODE=TRUE\n' > "${rc_path}"
unset AIRGEDDON_WINDOWS_HANDLING AIRGEDDON_DEBUG_MODE
env_vars_values_validation
[[ "${AIRGEDDON_WINDOWS_HANDLING}" == tmux && "${AIRGEDDON_DEBUG_MODE}" == true ]] || fail normalization

system_tmpdir="${work}/runtime/"
initialize_runtime_directory
[[ $(stat -c %a "${system_tmpdir}") == 700 ]] || fail permissions
AIRGEDDON_WINDOWS_HANDLING=xterm
instance_setter
first="${tmpdir}"
instance_setter
[[ "${first}" != "${tmpdir}" && -d "${first}" && -d "${tmpdir}" ]] || fail allocation
chmod 755 "${system_tmpdir}"
! initialize_runtime_directory 2>/dev/null || fail 'unsafe permissions accepted'
chmod 700 "${system_tmpdir}"

# Test firewall operations only through stubs.
iptables_nftables=1
iptables_cmd=fake_nft
fake_nft() { printf 'saved rules\n'; }
save_iptables_nftables
[[ $(cat "${system_tmpdir}${routing_tmp_file}") == 'saved rules' ]] || fail backup
fake_nft() { return 1; }
! save_iptables_nftables || fail 'backup failure ignored'
[[ $(cat "${system_tmpdir}${routing_tmp_file}") == 'saved rules' ]] || fail 'backup destroyed'
control_routing_status() { :; }
clean_initialize_iptables_nftables() { :; }
is_last_airgeddon_instance() { return 0; }
! clean_routing_rules 2>/dev/null || fail 'restore failure ignored'
[[ -f "${system_tmpdir}${routing_tmp_file}" ]] || fail 'recovery backup deleted'

# Validate responses before sourcing them; emulate curl without internet access.
http_proxy_detect() { http_proxy_set=0; }
timeout() { shift 3; "$@"; }
curl() {
 local destination
 while (($#)); do
  if [[ "$1" == -o ]]; then destination="$2"; shift; fi
  shift
 done
 cp "${work}/response" "${destination}"
 return "${curl_status:-0}"
}
printf '<html>Bad gateway</html>\n' > "${work}/response"
! download_validated_shell https://example.invalid "${work}/download" || fail HTML
printf '#!/usr/bin/env bash\nif then\n' > "${work}/response"
! download_validated_shell https://example.invalid "${work}/download" 2>/dev/null || fail syntax
printf '#!/usr/bin/env bash\ntrue\n' > "${work}/response"
download_validated_shell https://example.invalid "${work}/download" || fail 'valid shell'
curl_status=22
! download_validated_shell https://example.invalid "${work}/download" || fail 'HTTP failure'

# Failed language downloads must not replace the installed executable file.
printf 'original language file\n' > "${scriptfolder}${language_strings_file}"
! download_language_strings_file || fail 'failed language download accepted'
[[ $(cat "${scriptfolder}${language_strings_file}") == 'original language file' ]] || fail 'installed language file damaged'
curl_status=0
printf '#!/usr/bin/env bash\nfunction set_language_strings_version() { :; }\nlanguage_strings_version="wrong"\n' > "${work}/response"
! download_language_strings_file || fail 'mismatched language version accepted'
[[ $(cat "${scriptfolder}${language_strings_file}") == 'original language file' ]] || fail 'mismatched language file installed'

# Configuration precedence: nonempty environment wins even over duplicate keys.
AIRGEDDON_WINDOWS_HANDLING=TMUX
printf 'AIRGEDDON_WINDOWS_HANDLING=xterm\nAIRGEDDON_WINDOWS_HANDLING=xterm\n' > "${rc_path}"
env_vars_values_validation
[[ "${AIRGEDDON_WINDOWS_HANDLING}" == tmux ]] || fail 'environment precedence'

# Symlinked runtime roots must never be accepted.
original_runtime="${system_tmpdir}"
ln -s "${original_runtime}" "${work}/symlink"
system_tmpdir="${work}/symlink/"
! initialize_runtime_directory 2>/dev/null || fail 'runtime symlink accepted'
system_tmpdir="${original_runtime}"

cleanup_ready=1
cleanup_started=0
routing_modified=1
clean_routing_rules() { echo routing >> "${work}/cleanup"; }
clean_tmpfiles() { echo files >> "${work}/cleanup"; }
termination_cleanup
termination_cleanup
[[ $(wc -l < "${work}/cleanup") == 2 ]] || fail 'cleanup not idempotent'
echo 'All regression tests passed.'
