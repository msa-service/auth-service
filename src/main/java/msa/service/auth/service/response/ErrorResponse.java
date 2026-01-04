package msa.service.auth.service.response;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
public class ErrorResponse{
    private String errorCode;
    private String message;

    public static ErrorResponse create(String code, String message) {
        return new ErrorResponse(code, message);
    }
}
