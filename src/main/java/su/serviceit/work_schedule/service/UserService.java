package su.serviceit.work_schedule.service;

//import com.example.demo.dto.ScheduleDTO;

import su.serviceit.work_schedule.dto.UserDTO;
import su.serviceit.work_schedule.entity.User;
import su.serviceit.work_schedule.repository.ScheduleRepository;
import su.serviceit.work_schedule.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityNotFoundException;
import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ScheduleRepository scheduleRepository;

    public List<UserDTO> getAllUser() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(UserDTO::toModel)
                .collect(Collectors.toList());
    }

    public UserDTO getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Пользователь не найден"));
        return UserDTO.toModel(user);
    }

    public User getUserByUsername(String username) throws AccessDeniedException {
        // Загрузка данных пользователя из базы данных по его имени
        User user = userRepository.findByUsername(username);

        // Проверка, что текущий пользователь совпадает с запрашиваемым пользователем
        if (!user.getUsername().equals(SecurityContextHolder.getContext().getAuthentication().getName())) {
            throw new AccessDeniedException("У вас нет разрешения на доступ к этому ресурсу");
        }
        return user;
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public Long delete(Long id) {
        userRepository.deleteById(id);
        return id;
    }


    public boolean isCurrentUser(Long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof User) {
                User user = (User) principal;
                return user.getId().equals(userId);
            }
        }
        return false;
    }

}
