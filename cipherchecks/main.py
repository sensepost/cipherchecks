#!/usr/bin/env python3

import sys
import sslyze
import crayons


def scan_target(target, port) -> list:
    try:
        server_scan_req = sslyze.ServerScanRequest(
            server_location=sslyze.ServerNetworkLocation(hostname=target, port=port), scan_commands={sslyze.ScanCommand.CERTIFICATE_INFO,
                                                sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
                                                sslyze.ScanCommand.HEARTBLEED,
                                                sslyze.ScanCommand.ROBOT,
                                                sslyze.ScanCommand.SESSION_RENEGOTIATION,
                                                sslyze.ScanCommand.HTTP_HEADERS},
        )
    except sslyze.ServerHostnameCouldNotBeResolved:
        # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        return

    scanner = sslyze.Scanner()
    scanner.queue_scans([server_scan_req])

    accepted_ciphers = []

    for server_scan_result in scanner.get_results():

        if server_scan_result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("The target could not be contacted")
            continue

        ssl2_result = server_scan_result.scan_result.ssl_2_0_cipher_suites
        ssl3_result = server_scan_result.scan_result.ssl_3_0_cipher_suites
        tls1_0_result = server_scan_result.scan_result.tls_1_0_cipher_suites
        tls1_1_result = server_scan_result.scan_result.tls_1_1_cipher_suites
        tls1_2_result = server_scan_result.scan_result.tls_1_2_cipher_suites
        tls1_3_result = server_scan_result.scan_result.tls_1_3_cipher_suites

        if ssl2_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('SSL 2.0')))
            for accepted_cipher_suite in ssl2_result.result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if ssl3_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('SSL 2.0')))
            for accepted_cipher_suite in ssl3_result.result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_0_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('TLS 1.0')))
            for accepted_cipher_suite in tls1_0_result.result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_1_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('TLS 1.1')))
            for accepted_cipher_suite in tls1_1_result.result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_2_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for TLS 1.2:')
            for accepted_cipher_suite in tls1_2_result.result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)

        if tls1_3_result.result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for TLS 1.3:')
            for accepted_cipher_suite in tls1_3_result.result.accepted_cipher_suites:
                accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)

    return accepted_ciphers


def main():
    sys.tracebacklimit=0
    try:
        target = sys.argv[1]
        port = int(sys.argv[2])
    except KeyboardInterrupt:
        sys.exit(0)
    except IndexError:
        target = input('[+] target: ')
        port = int(input('[+] port: '))

    print('[+] Checking Accepted Cipher Suites for: {}'.format(crayons.green(target)))
    print('\nDepreciated protocols are shown in {}\nCBC Ciphers that also do not have PFS are shown in {}\nCBC Ciphers are shown in {}\nCiphers missing PFS are shown in {}'.format(crayons.red('red', bold=True),
                                                                                                                                                                                      crayons.magenta('magenta', bold=True),
                                                                                                                                                                                      crayons.yellow('yellow', bold=True),
                                                                                                                                                                                      crayons.blue('blue', bold=True)))
    for cipher in scan_target(target, port):
        print(cipher)


if __name__ == '__main__':
    main()
