package su.serviceit.work_schedule.controller.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import su.serviceit.work_schedule.dto.MenuDTO;
import su.serviceit.work_schedule.entity.Menu;
import su.serviceit.work_schedule.service.MenuService;

import java.nio.file.AccessDeniedException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class MenuController {
    private final MenuService menuService;

    @Autowired
    public MenuController(MenuService menuService) {
        this.menuService = menuService;
    }
    @GetMapping("/menus")
    public List<MenuDTO> getAllMenus() throws AccessDeniedException{
        return menuService.getAllMenus();
    }
}

