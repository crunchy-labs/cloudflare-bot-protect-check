# cloudflare-bot-protect-check [![Top language](https://img.shields.io/github/languages/top/crunchy-labs/cloudflare-bot-protect-check)](https://github.com/crunchy-labs/cloudflare-bot-protect-check)

A simple cli tool to check which user agents are valid for cloudflare protected websites.

## About

This tool is developed with a special focus on our projects like [crunchyroll-rs](https://github.com/crunchy-labs/crunchyroll-rs) or [crunchy-cli](https://github.com/crunchy-labs/crunchy-cli) to see how to bypass the bot protection installed for [www.crunchyroll.com](https://www.crunchyroll.com).
But nevertheless it can be used for other sites and projects too.
Especially _Rust_ projects which need to bypass the cloudflare bot check might benefit from this tool as it uses [reqwest](https://github.com/seanmonstar/reqwest) and [rustls](https://github.com/rustls/rustls) which behaves other than e.g. the python [requests](https://pypi.org/project/requests/) package.

## Installation

To build this tool, [git](https://git-scm.com/) and [Cargo](https://doc.rust-lang.org/cargo) are required.
If these requirements are met, continue with executing the following commands.
```shell
$ git clone https://github.com/crunchy-labs/cloudflare-bot-protect-check
$ cd cloudflare-bot-protect-check
# either just build it (will be available in ./target/release/cloudflare-bot-protect-check)...
$ cargo build --release
# ... or install it globally
$ cargo install --force --path .
```

## Usage

By default, this tool reads user agents from stdin.
```shell
# user agent from stdin
$ echo "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" | cloudflare-bot-protect-check https://www.crunchyroll.com
```

If you want to read the user agents from a file, use the `--file` flag.
The file must be text file where every line contains one user agent.
```shell
# assuming that the file 'useragents.txt' with the following content exists
$ cat useragents.txt
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 13.4; rv:109.0) Gecko/20100101 Firefox/115.0
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
# read the user agents from 'useragents.txt'
$ cloudflare-bot-protect-check --file useragents.txt https://www.crunchyroll.com
```

The default output format is plain text.
Use the `--format` flag to change the output format.
Available formats are `plain` and `json`.
```shell
$ cloudflare-bot-protect-check --format json https://www.crunchyroll.com
```

Some flags to set custom tls settings are available too.
You need to set the `--custom-tls` flag to activate the custom tls settings.
Use `cloudflare-bot-protect-check --help` to see all available flag values.
```shell
$ cloudflare-bot-protect-check --custom-tls https://www.crunchyroll.com
# set specific cipher suite(s) with `--cipher-suite`
$ cloudflare-bot-protect-check --custom-tls --cipher-suite tls13-aes-256-gcm-sha384 https://www.crunchyroll.com
# set specific key exchange group(s) with `--kx-group`
$ cloudflare-bot-protect-check --custom-tls --kx-group x25519 https://www.crunchyroll.com
# set specific tls version(s) with `--tls`
$ cloudflare-bot-protect-check --custom-tls --tls tls12 --tls tls13 https://www.crunchyroll.com
```

## Resources

### Where to get user agents

- [whatsismybrowser.com](https://www.whatismybrowser.com/) has a large [user agent database](https://explore.whatismybrowser.com/useragents/explore/) with is also available via an api (only limited access, also has a paid plan)
- [useragents.me](https://www.useragents.me/) provides the most common and latest used user agents as json. You can use the following expression to get all user agents from an useragents.me user agent json list
  ```shell
  $ cat <json-from-useragents.me-as-file> | grep -oP '(?<="ua":\s").+?(?=")'
  ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for more details.
