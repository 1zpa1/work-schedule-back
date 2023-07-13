package su.serviceit.work_schedule.controller;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import su.serviceit.work_schedule.dto.UserDTO;
import su.serviceit.work_schedule.entity.User;
import su.serviceit.work_schedule.service.UserService;

import java.nio.file.AccessDeniedException;
import java.util.List;

@RestController
@RequestMapping("api/")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class UserController {

    private final UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserDTO> allUsers() throws AccessDeniedException {
        return userService.getAllUser();
    }

    @GetMapping("user/profile")
    public ResponseEntity<UserDTO>
    viewUserProfile(@AuthenticationPrincipal KeycloakPrincipal<KeycloakSecurityContext> principal)
            throws AccessDeniedException {
        KeycloakSecurityContext keycloakSecurityContext = principal.getKeycloakSecurityContext();
        AccessToken accessToken = keycloakSecurityContext.getToken();
        String email = accessToken.getEmail();
        String username = accessToken.getPreferredUsername();
        String firstName = accessToken.getGivenName();
        String lastName = accessToken.getFamilyName();
        /*
         Создаем новый объект UserDTO для возврата информации о пользователе
         */
        UserDTO userDTO = new UserDTO();
        userDTO.setUserName(username);
        userDTO.setEmail(email);
        userDTO.setFirstName(firstName);
        userDTO.setLastName(lastName);

        return ResponseEntity.ok(userDTO);
    }


    @GetMapping("admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDTO getUserById(@PathVariable Long id) {
        return userService.getUserById(id);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public void addUser(@RequestBody User user) {
        userService.save(user);
    }

    @DeleteMapping("admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}
