require "../spec_helper"
require "../../src/jwt/jwks_proxy"

describe "JWT::JWKS proxy support" do
  it "tunnels through the proxy in the environment" do
    server = TCPServer.new("127.0.0.1", 0)
    requests = Channel(String).new(1)
    spawn do
      if socket = server.accept?
        request = socket.gets.to_s
        while (line = socket.gets) && !line.empty?
        end
        socket << "HTTP/1.0 200 Connection established\r\n\r\n"
        socket.flush
        requests.send request
      end
    end

    previous = ConnectProxy.proxy_uri
    ConnectProxy.proxy_uri = "http://127.0.0.1:#{server.local_address.port}"
    begin
      client = JWT::JWKS.new.http_client(URI.parse("http://idp.example.com/keys"))
      requests.receive.should eq "CONNECT idp.example.com:80 HTTP/1.0"
      client.close
    ensure
      ConnectProxy.proxy_uri = previous
      server.close
    end
  end
end
