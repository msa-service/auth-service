package msa.service.auth.domain.exception;

import org.springframework.http.HttpStatus;

public class ApiBadGateway extends BaseException{
    public ApiBadGateway(String msg) {
        super(msg);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.BAD_GATEWAY;
    }

    @Override
    public String getErrorCode() {
        return "BAD_GATEWAYs";
    }
}
