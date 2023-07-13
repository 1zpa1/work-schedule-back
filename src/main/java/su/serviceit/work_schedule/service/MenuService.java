package su.serviceit.work_schedule.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import su.serviceit.work_schedule.dto.MenuDTO;
import su.serviceit.work_schedule.dto.UserDTO;
import su.serviceit.work_schedule.entity.Menu;
import su.serviceit.work_schedule.entity.User;
import su.serviceit.work_schedule.repository.MenuRepository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class MenuService {
    private final MenuRepository menuRepository;

    @Autowired
    public MenuService(MenuRepository menuRepository) {
        this.menuRepository = menuRepository;
    }

    public List<MenuDTO> getAllMenus() {
        List<Menu> menus = menuRepository.findAll();
        return menus.stream()
                .map(MenuDTO::toModel)
                .collect(Collectors.toList());
    }
}
