package org.sample;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.dropwizard.DropwizardMetricsOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.JWTAuthHandler;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class App {

    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) {
        System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.Log4j2LogDelegateFactory");
        logger.info("start app");
        Vertx vertx = Vertx.vertx(new VertxOptions().setMetricsOptions(
                new DropwizardMetricsOptions().setEnabled(true)
        ));
        vertx.createHttpServer(getOptions())
                .requestHandler(getRouter(vertx)::accept)
                .listen();
    }

    private static HttpServerOptions getOptions() {
        return new HttpServerOptions()
                    .setSsl(true)
                    .setKeyStoreOptions(new JksOptions()
                            .setPath("keystore.jks")
                            .setPassword("changeit"))
                    .setPort(8080);
    }

    private static Router getRouter(Vertx vertx) {
        Router router = Router.router(vertx);
        JWTAuth jwt = getJwtAuth(vertx);
        router.route("/api/*").handler(JWTAuthHandler.create(jwt, "/login"));
        router.get("/").handler(req -> req.response().end("Hello World!"));
        router.get("/api/secure").handler(req -> req.response().end("Hello World from secure!"));
        router.put("/login").handler(login(jwt));
        return router;
    }

    private static Handler<RoutingContext> login(JWTAuth jwt) {
        return req -> {
            String username = req.request().getParam("username");
            String password = req.request().getParam("password");
            logger.info("try to login user: {}, {}", username, req.toString());
            if ("humberto".equals(username) && "secret".equals(password)) {
                logger.info("login success");
                String token = jwt.generateToken(new JsonObject().put("sub", "humberto"), new JWTOptions().setExpiresInSeconds(60L));
                req.response().putHeader("Content-Type", "text/plain");
                req.response().end(token);
            } else {
                logger.info("login failure!");
                req.fail(401);
            }
        };
    }

    private static JWTAuth getJwtAuth(Vertx vertx) {
        return JWTAuth.create(vertx, new JsonObject()
                    .put("keyStore", new JsonObject()
                            .put("type", "jceks")
                            .put("path", "keystore.jceks")
                            .put("password", "secret")));
    }
}
