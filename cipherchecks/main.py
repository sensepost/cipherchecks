#!/usr/bin/env python3

import sys
import sslyze
import crayons


def connect_target(target):
    server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(target, 443)
    server_info = sslyze.ServerConnectivityTester().perform(server_location)
    return server_info


def scan_target(server_info) -> None:
    scanner = sslyze.Scanner()
    server_scan_req = sslyze.ServerScanRequest(
        server_info=server_info, scan_commands={sslyze.ScanCommand.CERTIFICATE_INFO,
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
    scanner.queue_scan(server_scan_req)
    return scanner.get_results()


def parse_results(results):
    accepted_ciphers = []

    for server_scan_result in results:
        ssl2_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES]
        ssl3_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES]
        tls1_0_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES]
        tls1_1_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES]
        tls1_2_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES]
        tls1_3_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES]

        if ssl2_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('SSL 2.0')))
            for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if ssl3_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('SSL 2.0')))
            for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_0_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('TLS 1.0')))
            for accepted_cipher_suite in tls1_0_result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_1_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for {}:'.format(crayons.red('TLS 1.1')))
            for accepted_cipher_suite in tls1_1_result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)
                    
        if tls1_2_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for TLS 1.2:')
            for accepted_cipher_suite in tls1_2_result.accepted_cipher_suites:
                if 'CBC' in str(accepted_cipher_suite) and 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.magenta(accepted_cipher_suite.cipher_suite.name))
                elif 'CBC' in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.yellow(accepted_cipher_suite.cipher_suite.name))
                elif 'DHE' not in str(accepted_cipher_suite):
                    accepted_ciphers.append('\t' + '- ' + crayons.blue(accepted_cipher_suite.cipher_suite.name))
                else:
                    accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)

        if tls1_3_result.accepted_cipher_suites:
            accepted_ciphers.append('\nAccepted Ciphers for TLS 1.3:')
            for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                accepted_ciphers.append('\t' + '- ' + accepted_cipher_suite.cipher_suite.name)

    return accepted_ciphers


def main():
    try:
        target = sys.argv[1]
    except IndexError:
        target = input('[+] target: ')

    print('[+] Checking Accepted Cipher Suites for: {}'.format(crayons.green(target)))
    print('\nCBC Ciphers that also do not have PFS are shown in {}\nCBC Ciphers are shown in {}\nCiphers missing PFS are shown in {}'.format(crayons.magenta('magenta',
                                                                                                                                                             bold=True),
                                                                                                                                             crayons.yellow('yellow',
                                                                                                                                                            bold=True),
                                                                                                                                             crayons.blue('blue',
                                                                                                                                                          bold=True)))
    results = scan_target(connect_target(target))
    for cipher in parse_results(results):
        print(cipher)


if __name__ == '__main__':
    main()
