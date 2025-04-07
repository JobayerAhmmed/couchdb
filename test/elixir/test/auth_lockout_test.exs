defmodule AuthLockoutTest do
  use CouchTestCase

  @moduletag :authentication

  @moduletag config: [
               {
                 "admins",
                 "chttpd_auth_lockout",
                 "bar"
               }
             ]

  test "lockout after multiple failed authentications", _context do
    server_config = [
      %{
        :section => "chttpd_auth_lockout",
        :key => "mode",
        :value => "enforce"
      }
    ]

    run_on_modified_server(
      server_config,
      fn -> test_chttpd_auth_lockout_enforcement() end
    )
  end

  defp test_chttpd_auth_lockout_enforcement do
    #
    # Updated by: Jobayer Ahmmed
    # Get threshold, default is 5
    #
    threshold = 5
    config_url = "/_node/node1@127.0.0.1/_config/chttpd_auth_lockout/threshold"
    resp = Couch.get(config_url)

    threshold =
      if resp.status_code == 200 do
        with true <- is_binary(resp.body),
          trimmed <- String.trim(resp.body),
          true <- trimmed != "",
          {value, ""} <- Integer.parse(trimmed) do
            value
        else
        _ -> threshold
        end
      else
        threshold
      end

    # exceed the lockout threshold
    if threshold > 0 do
      for _n <- 1..threshold do
        resp = Couch.get("/_all_dbs",
          no_auth: true,
          headers:  [authorization: "Basic #{:base64.encode("chttpd_auth_lockout:baz")}"]
          )
        assert resp.status_code == 401
      end
    else
      resp = Couch.get("/_all_dbs",
        no_auth: true,
        headers:  [authorization: "Basic #{:base64.encode("chttpd_auth_lockout:baz")}"]
        )
      assert resp.status_code == 401
    end

    # locked out?
    resp = Couch.get("/_all_dbs",
      no_auth: true,
      headers:  [authorization: "Basic #{:base64.encode("chttpd_auth_lockout:baz")}"]
    )
    assert resp.status_code == 403
    assert resp.body["reason"] == "Account is temporarily locked due to multiple authentication failures"
  end

  defp test_chttpd_auth_lockout_warning do
    # exceed the lockout threshold
    for _n <- 1..5 do
      resp = Couch.get("/_all_dbs",
        no_auth: true,
        headers:  [authorization: "Basic #{:base64.encode("chttpd_auth_lockout:baz")}"]
        )
      assert resp.status_code == 401
    end

    # warning?
    resp = Couch.get("/_all_dbs",
      no_auth: true,
      headers:  [authorization: "Basic #{:base64.encode("chttpd_auth_lockout:baz")}"]
    )
  end

end
