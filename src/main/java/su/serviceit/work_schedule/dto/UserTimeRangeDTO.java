package su.serviceit.work_schedule.dto;

import su.serviceit.work_schedule.entity.Schedule;
import su.serviceit.work_schedule.entity.TimeRange;
import su.serviceit.work_schedule.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserTimeRangeDTO {
    private String userName;
    private List<Schedule> schedules;

    public static UserTimeRangeDTO toModel(User entity, TimeRange timeRange) {
        UserTimeRangeDTO model = new UserTimeRangeDTO();
        model.setUserName(entity.getUsername());
        model.setSchedules((List<Schedule>) timeRange.getSchedule());
        return model;
    }
}
