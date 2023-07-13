package su.serviceit.work_schedule.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "sec_schedules")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Schedule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "dt_date")
    private LocalDate date;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "schedule")
    private List<TimeRange> timeRanges;
}
