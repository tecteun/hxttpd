package hxttpd;

import neko.Lib;
import sys.net.Socket;
import neko.net.ThreadServer;
import haxe.io.Bytes;
import haxe.io.Path;
import sys.io.File;
import sys.ssl.Certificate;
import sys.ssl.Key;
import sys.net.Host; 

typedef HxttpdClient = {
  var id : Int;
  var sock : Socket;
}

typedef HxttpdMessage = {
  var request:HxttpRequest; 
  var body : Bytes;
}

typedef HxttpdRouteResult = {bytes:haxe.io.Bytes, ?response:HxttpResponse};
typedef HxttpdRenderFunction = HxttpRequest-> //request headers
                                HxttpResponse->
                                  Path-> //request path
                                      ?HxttpdRouteResult-> //chained result
                                      HxttpdRouteResult;


class HxttpRequest {
  public var httpStatusLine:{ ?method:String, ?request_uri:String, ?http_version:String } = {};
  public var headers:Map<String, String> = new Map();
  
  public function new(?method:String = "GET", ?request_uri = "/", ?http_version:String = "HTTP/1.1"){
    httpStatusLine.method = method;
    httpStatusLine.request_uri = request_uri;
    httpStatusLine.http_version = http_version;
  }
  public static function parse(rawrequest:Array<String>):HxttpRequest{
    var statusline = rawrequest.shift().split(" ");
    var retval = new HxttpRequest(statusline[0], statusline[1], statusline[2]);
    for(s in rawrequest){
      var line = s.split(":");
      if(line.length > 1)
        retval.headers.set(StringTools.trim(line[0]), StringTools.trim(line[1]));
    }
    return retval;
  }
  public function toString(){
    var h = [];
    for(k in headers.keys()){
      h.push('${k}: ${headers.get(k)}');
    }
    return '${httpStatusLine.method} ${httpStatusLine.request_uri} ${httpStatusLine.http_version}\r\n' + h.join("\r\n") + "\r\n\r\n";
  }
}

//https://tools.ietf.org/html/rfc2616#section-6
class HxttpResponse {
  public var httpStatusLine:{ ?status_code:Int, ?http_version:String, ?reason_phrase:String } = {};
  public var headers:Map<String, String> = new Map();
  public function new(?status_code:Int = 200, ?reason_phrase = "OK", ?http_version:String = "HTTP/1.1"){
    httpStatusLine.status_code = status_code;
    httpStatusLine.reason_phrase = reason_phrase;
    httpStatusLine.http_version = http_version;
  }
  public function toString(){
    var h = [];
    for(k in headers.keys()){
      h.push('${k}: ${headers.get(k)}');
    }
    return '${httpStatusLine.http_version} ${httpStatusLine.status_code} ${httpStatusLine.reason_phrase}\r\n' + h.join("\r\n") + "\r\n\r\n";
  }
}

class Hxttpd extends ThreadServer<HxttpdClient, HxttpdMessage>
{
  private static inline var MAX_CONNECTIONS:Int = 128;
  private static inline var MAX_SOCKETS_PER_THREAD:Int = 64;
  private static inline var CLIENT_TIMEOUT:Int = 30;
  private static inline var SERVER_TIMEOUT:Int = 30;
  private static inline var THREAD_COUNT:Int = 150;

  var debug:Bool;
  var secure:Bool;
  var server_base_path:Path;
  public function new(ip:String = "localhost", ?port:Int = 1234, ?base_path:String = ".", ?secure:Bool = false, ?debug:Bool = false){
    super();
    this.server_base_path = new Path(base_path);
    this.secure = secure;
    this.debug = debug;
    this.listen = MAX_CONNECTIONS;
    this.nthreads = THREAD_COUNT;
    this.maxSockPerThread = MAX_SOCKETS_PER_THREAD;
    haxe.EntryPoint.addThread(run.bind(ip, port));
  }
  // create a Client
  override function clientConnected( s : Socket ) : HxttpdClient
  {
    var num = Std.random(100);
    if(debug)
      Lib.println("client " + num + " is " + s.peer());
    return { id: num, sock: s };
  }

  override function clientDisconnected( c : HxttpdClient )
  {
    if(debug)
      Lib.println("client " + Std.string(c.id) + " disconnected");
  }

  override function readClientMessage(c:HxttpdClient, buf:Bytes, pos:Int, len:Int)
  {
    // find out if there's a full message, and if so, how long it is.
    var eof = 0;
    var complete = false;
    var cpos = pos;
    while (cpos < (pos+len) && !complete)
    {
      //check complete request /CR/LF/CR/LF
      var lastChar = buf.get(cpos);
      if(lastChar == 10 || lastChar == 13){
        eof ++;
      }else{
        eof = 0;
      }
      complete = eof >= 4;
      cpos++;
    }

    // no full message
    if( !complete ) return null;
    // got a full message, return it
    var msg:String = buf.getString(pos, cpos-pos);
    
    return {msg: { request: HxttpRequest.parse(msg.split("\r\n")), body: null }, bytes: cpos-pos};
  }

  override function clientMessage( c : HxttpdClient, msg : HxttpdMessage )
  {
    //handle rendering in separate thread:
    neko.vm.Thread.create(function(){
      var responseBytes:haxe.io.Bytes = null;
      var response  = new HxttpResponse(200);
      var request = msg.request;
      try{
        var path = new Path(request.httpStatusLine.request_uri);
        var route_result:HxttpdRouteResult = null;
        if(path.file == "" && path.ext == null){
          path.file = "index";
          path.ext = "html";
        }
        //https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html
        response.headers.set("Server", Macro.GetVersion("hxttpd"));
        response.headers.set("Content-Type", (switch(path.ext){
            case "svg": "image/svg+xml";
            case "html": "text/html";
            case "ico": "image/x-icon";
            case "js": "application/javascript";
            default: "";
          }));

        for(r in routes)
          for(ereg in r.path)
            if(ereg.match(path.dir)){
              var value = try{
                r.renderFunction(request, response, path, route_result);
              }catch(e:Dynamic){  { bytes:haxe.io.Bytes.ofString('$e\n\rwhile fetching\n\r${path}') }; }
              if(value != null)
                route_result = value;      
              if(route_result != null && route_result.response != null)
                response = route_result.response;
              break;
            }
        
        if(responseBytes == null)
          responseBytes = route_result != null ? route_result.bytes : File.getBytes('${server_base_path.dir}${path}');
        response.headers.set("Content-Length", Std.string(responseBytes.length));

      }catch(error:Dynamic){
        var responseBody = '🔥🚒 Hxttpd.hx 🧐\n'; 
        responseBody += 'Error: ${response.httpStatusLine.status_code}, ${response.httpStatusLine.reason_phrase}\n$error\n';
        responseBody += haxe.CallStack.toString(haxe.CallStack.callStack()); 
        responseBody += '\r\n';                
        responseBody += '\nRequest Headers:\n$request';                
        responseBody += '\nResponse Headers:\n$response';                
        responseBody += "\r\n";
        responseBytes = haxe.io.Bytes.ofString(responseBody);
        response  = new HxttpResponse(404, "Not Found");
        response.headers.set("Content-Type", "text/plain; charset=utf-8");
        response.headers.set("Content-Length", Std.string(responseBytes.length));
        
        if(debug){
          Sys.println("=== READ ERROR ==="); 
          Sys.println(request.toString()); 
          Sys.println(error);
        } 
      }
      if(request.headers.exists("Connection")){
        response.headers.set("Connection", request.headers.get("Connection"));
      }else{
        response.headers.set("Connection", "close");
      }
      //Build response buffer
      var b = new haxe.io.BytesBuffer();
      b.add(haxe.io.Bytes.ofString(response.toString()));
      if(responseBytes != null)
        b.add(responseBytes);
      

      c.sock.output.prepare(responseBytes.length);
      /* ugly blocking mode:
        try{
          c.sock.setBlocking(true);
          c.sock.output.write(b.getBytes());
          c.sock.setBlocking(false);
        }catch(e:Dynamic){
          if(debug){
            Sys.println("=== WRITE ERROR ==="); 
            Sys.println('Unable to write outgoing response : $e'); 
          }
        }
      */
      var i = new haxe.io.BytesInput(b.getBytes());
      var chunkSize = 4096;
      while(true){
        try{
          c.sock.output.writeInput(i, chunkSize);
          if(i.position == i.length)
            break;
        }catch(e:Dynamic){
          if(e == 'Blocking' || (Std.is(e, haxe.io.Error) && (
                  (e:haxe.io.Error).match(haxe.io.Error.Custom(haxe.io.Error.Blocked)) ||
                  (e:haxe.io.Error).match(haxe.io.Error.Blocked)))){
            //retry chunk
            i.position -= chunkSize;
            continue;
          }else{
            if(debug){
              Sys.println("=== WRITE ERROR ==="); 
              Sys.println('Unable to write outgoing response : $e'); 
            } break;
          }
        }
      }

      if(response.headers.get("Connection") == "close")
        this.stopClient(c.sock);

      if(debug)
        debugRequest(request, response);
    });
  }

  /**
		Start the server at the specified host and port.
	**/
	override public function run( host:String, port:Int ) {
    Sys.println("Starting server on: " + host + ":" + port + " serving: " + server_base_path); 
    sock = if(secure){
      //some https stuff:
      //https://github.com/pperidont/haxe-ssl-tests/blob/2a748fa0e076ae5e70b698ba045aeaeba18fa08a/src/TestServer.hx
      var sslSocket = new sys.ssl.Socket();
      sslSocket.setCA( Certificate.loadFile("certificate/cert/root.crt") );
      sslSocket.setCertificate( Certificate.loadFile("certificate/cert/localhost.crt"), Key.readPEM(File.getContent("certificate/cert/localhost.key"), false) );
      // sslSocket.addSNICertificate( function(s){ Sys.println("Client SNI="+s); return s == "foo.bar"; }, Certificate.loadFile("cert/foo.bar.crt"), Key.readPEM(File.getContent("cert/foo.bar.key"), false) );
      // sslSocket.addSNICertificate( function(s) return s == "unknown.bar", Certificate.loadFile("cert/unknown.bar.crt"), Key.readPEM(File.getContent("cert/unknown.bar.key"), false) );
      sslSocket.verifyCert = false;
      sslSocket;
    }else{
      new sys.net.Socket();
    }
    
    sock.setTimeout(SERVER_TIMEOUT);
    #if neko
    var keepalive:Dynamic = neko.Lib.load("std", "socket_set_keepalive", 4);
    try{
      keepalive( @:privateAccess sock.__s, false, null, null );
    }catch(e:Dynamic){ 
      if(debug){ 
        Sys.println("Failed to disable keepalive -> " + e);
      } 
    } 
    #end

		sock.bind(new Host(host),port);
		sock.listen(listen);
		init();
		while( true ) {
			try {
        var client = sock.accept();
        client.setTimeout(CLIENT_TIMEOUT);
        #if neko
        try{
          keepalive( @:privateAccess client.__s, false, null, null );
        }catch(e:Dynamic){ 
          if(debug){ 
            Sys.println("Failed to disable keepalive -> " + e);
          } 
        } 
        #end
				addSocket(client);
			} catch( e : Dynamic ) {
				logError(e);
			}
		}
	}

  private function debugRequest(request:HxttpRequest, response:HxttpResponse) : Void {
    Sys.println('Request:\n${request.toString()}'); 
    Sys.println("");  
    Sys.println('Response:\n${response.toString()}'); 
  }

  private var routes:List<{ path:Array<EReg>, renderFunction:HxttpdRenderFunction}> = new List();
  public function addRoute(path:Array<EReg>, renderFunction:HxttpdRenderFunction) : Void 
    routes.add({path:path, renderFunction:renderFunction});

  /*
    //handshake not necessary when using socket read methods, not .input .output
    private function handleSSL(socket:sys.net.Socket):sys.ssl.Socket{
      var ssl_client:sys.ssl.Socket = null;
      try ssl_client = cast(socket, sys.ssl.Socket).accept() catch(e:Dynamic){ trace("failed to accept " + e);};
      while(true && null != ssl_client){
        try{
          ssl_client.handshake();
          break;
        }catch(e:Dynamic){
          if(debug){
            Sys.println('SSL handshake ${Date.now()} ${e}');
          }
          switch (Std.string(e)) {
            case "Blocking": continue;
            case "Blocked": break;
            case "SSL - No client certification received from the client, but required by the authentication mode": ssl_client.output.flush(); continue; //fix for chrome
            case "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed": break;
            default:
              closeSocket(ssl_client);
              ssl_client = null;
              if(debug)
                Util.showException(e);
              break;
          }
        }
      }
      if(null != ssl_client)
        ssl_client.output.flush();
      return ssl_client;
    }
  */

  //fix for ssl
  override function readClientData( c ) {
    try{
      super.readClientData(c);
    } catch( e : Dynamic ) {
      if(e == 'Blocking' || (Std.is(e, haxe.io.Error) && (
              (e:haxe.io.Error).match(haxe.io.Error.Custom(haxe.io.Error.Blocked)) ||
              (e:haxe.io.Error).match(haxe.io.Error.Blocked)))){
          //ignore ssl read blocked (busy with handshake)
      }else{
        throw e;
      }
    }
  }
  public static var status_codes:Map<Int, String> = [
    100 => "Continue",
    101 => "Switching Protocols",
    200 => "OK",
    201 => "Created",
    202 => "Accepted",
    203 => "Non-Authoritative Information",
    204 => "No Content",
    205 => "Reset Content",
    206 => "Partial Content",
    300 => "Multiple Choices",
    301 => "Moved Permanently",
    302 => "Found",
    303 => "See Other",
    304 => "Not Modified",
    305 => "Use Proxy",
    307 => "Temporary Redirect",
    400 => "Bad Request",
    401 => "Unauthorized",
    402 => "Payment Required",
    403 => "Forbidden",
    404 => "Not Found",
    405 => "Method Not Allowed",
    406 => "Not Acceptable",
    407 => "Proxy Authentication Required",
    408 => "Request Time-out",
    409 => "Conflict",
    410 => "Gone",
    411 => "Length Required",
    412 => "Precondition Failed",
    413 => "Request Entity Too Large",
    414 => "Request-URI Too Large",
    415 => "Unsupported Media Type",
    416 => "Requested range not satisfiable",
    417 => "Expectation Failed",
    500 => "Internal Server Error",
    501 => "Not Implemented",
    502 => "Bad Gateway",
    503 => "Service Unavailable",
    504 => "Gateway Time-out",
    505 => "HTTP Version not supported"
 ];
}