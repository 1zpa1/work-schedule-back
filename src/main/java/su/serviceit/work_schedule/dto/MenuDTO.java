package su.serviceit.work_schedule.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import su.serviceit.work_schedule.entity.Menu;

@Data
public class MenuDTO {
        private String title;
        private String icon;
        private String route;

    public static MenuDTO toModel(Menu menu) {
        MenuDTO menuDTO = new MenuDTO();
        menuDTO.setTitle(menu.getTitle());
        menuDTO.setIcon(menu.getIcon());
        menuDTO.setRoute(menu.getRoute());
        return menuDTO;
    }
}

