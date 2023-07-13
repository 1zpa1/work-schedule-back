package su.serviceit.work_schedule.dto;

import su.serviceit.work_schedule.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    private String userName;
    private String firstName;
    private String lastName;
    private String email;

    public static UserDTO toModel(User entity) {
        UserDTO model = new UserDTO();
        model.setUserName(entity.getUsername());
        model.setFirstName(entity.getFirstName());
        model.setLastName(entity.getLastName());
        model.setEmail(entity.getEmail());
        return model;
    }

}
