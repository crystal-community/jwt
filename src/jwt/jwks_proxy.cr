# Optional HTTP proxy support for `JWT::JWKS`.
#
# Crystal's `HTTP::Client` ignores proxy environment variables. Requiring this
# file makes OIDC metadata and JWKS fetches tunnel through the proxy named by
# `https_proxy`, `http_proxy`, `HTTPS_PROXY` or `HTTP_PROXY` (credentials from
# the URL or `PROXY_USERNAME` / `PROXY_PASSWORD`), and connect directly when
# none is set.
#
# Needs the `connect-proxy` shard, which applications must add themselves:
#
# ```yaml
# dependencies:
#   connect-proxy:
#     github: spider-gazelle/connect-proxy
# ```
#
# ```
# require "jwt/jwks_proxy"
# ```
require "connect-proxy"
require "./jwks"

module JWT
  class JWKS
    def http_client(uri : URI) : HTTP::Client
      client = ConnectProxy::HTTPClient.new(uri, ignore_env: true)
      client.connect_timeout = HTTP_CONNECT_TIMEOUT
      client.read_timeout = HTTP_READ_TIMEOUT
      # opened after the timeouts are set so they cover the proxy connection
      if ConnectProxy.behind_proxy?
        client.set_proxy ConnectProxy.new(*ConnectProxy.parse_proxy_url)
      end
      client
    end
  end
end
