package msa.service.auth.infra.oauth;

import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.NotImplementedException;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Component
public class OauthLoginStrategyResolver {

    private final Map<LoginType, OauthLoginStrategy> strategyMap;

    // spring boot가 알아서 주입해줌.
    public OauthLoginStrategyResolver(List<OauthLoginStrategy> strategyList) {
        Map<LoginType, OauthLoginStrategy> map = new EnumMap<>(LoginType.class);

        for (OauthLoginStrategy st: strategyList) {
            map.put(st.supports(), st);
        }

        strategyMap = Map.copyOf(map);
    }

    public OauthLoginStrategy resolve(LoginType type) {
        OauthLoginStrategy res = strategyMap.get(type);

        if (res == null) {
            // enum에 새로운 방식을 들록했지만 OauthLoginStrategy를 등록하지 않은 상황.
            throw new NotImplementedException(
                    "OauthLoginStrategyResolver.resolve(): unsupported type=" + type
            );
        }

        return res;
    }

}
